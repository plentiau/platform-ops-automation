import os
import json
import requests
import logging
import boto3
import time

from datetime import datetime, timezone
from botocore.exceptions import ClientError

# Setup logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
numeric_level = getattr(logging, LOG_LEVEL, logging.INFO)
logging.basicConfig(
    level=numeric_level,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

logger = logging.getLogger(__name__)

ZEROSSL_URL = "https://api.zerossl.com"
CERTIFICATE_VALIDITY_FILE = "certificate_validity"
REMAINING_DAY_THRESHOLD = 14


def get_certificate_detail(certificate_id: str, retries: int = 3, sleep_seconds: int = 5):
    """
    Fetch certificate detail from ZeroSSL API, retrying on failure with a fixed delay.

    Args:
        certificate_id (str): ZeroSSL certificate ID.
        retries (int): Number of retries on failure (default 3).
        sleep_seconds (int): Seconds to wait between retries (default 5).

    Returns:
        tuple: (success: bool, response_json: dict or None)
    """
    access_key = os.getenv("ZEROSSL_API_KEY")
    if not access_key:
        raise RuntimeError("ZEROSSL_API_KEY environment variable is not set")
    
    url = f"{ZEROSSL_URL}/certificates/{certificate_id}?access_key={access_key}"

    for attempt in range(1, retries + 1):
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return True, response.json()
        except requests.RequestException as e:
            logger.error(
                f"Attempt {attempt} failed to get certificate details for ID '{certificate_id}'. Error: {e}"
            )
            if attempt < retries:
                logger.info(f"Retrying in {sleep_seconds} seconds...")
                time.sleep(sleep_seconds)
            else:
                logger.error("All retries failed.")
                return False, None


def get_active_microservices(environment: str):
    """Get active microservices for the environment from AWS Secrets Manager."""
    client = boto3.client("secretsmanager")
    try:
        paginator = client.get_paginator("list_secrets")
        secrets = []
        for page in paginator.paginate():
            for secret in page.get("SecretList", []):
                name = secret["Name"]
                if name.startswith(f"/{environment}/services/") and name.endswith("/zerossl_certificate"):
                    # Extract microservice name
                    parts = name.split("/")
                    if len(parts) >= 4:
                        secrets.append(parts[3])
        if not secrets:
            logger.error(f"No secrets found for environment: {environment}")
            return False, None
        return True, sorted(set(secrets))
    except ClientError as e:
        logger.error(f"AWS error while listing secrets: {e}")
        return False, None


def get_certificate_id(environment: str, microservice: str):
    """Fetch the certificate ID from AWS Secrets Manager."""
    client = boto3.client("secretsmanager")
    secret_name = f"/{environment}/services/{microservice}/zerossl_certificate"
    try:
        # Check if secret exists
        response = client.get_secret_value(SecretId=secret_name)
        secret_string = response.get("SecretString")
        if not secret_string:
            logger.error(f"Secret '{secret_name}' exists but has no SecretString!")
            return False, None

        secret_obj = json.loads(secret_string)
        if "id" in secret_obj:
            return True, secret_obj["id"]
        else:
            logger.error(f"Key 'id' not found in secret '{secret_name}'!")
            return False, None
    except ClientError as e:
        logger.error(f"Error fetching secret {secret_name}: {e}")
        return False, None


def determine_expiration_date(certificate_detail: dict):
    """Check if certificate is issued and still valid, return remaining days."""
    if certificate_detail.get("status") == "issued":
        expiry_date = datetime.strptime(certificate_detail["expires"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)

        if expiry_date >= now:
            days_remaining = (expiry_date - now).days
            logger.info(
                f"Certificate for {certificate_detail.get('common_name')} valid until {expiry_date} ({days_remaining} days)"
            )
            return True, days_remaining
        else:
            logger.error(f"Certificate for {certificate_detail.get('common_name')} expired on {expiry_date}!")
            return False, None
    else:
        logger.error(
            f"Certificate for {certificate_detail.get('common_name')} not issued (status: {certificate_detail.get('status')})"
        )
        return False, None

def evaluate_expiration(environment: str, microservice: str, filename: str = None):
    """Evaluate expiration for one microservice's certificate and optionally log to a file."""
    ok, certificate_id = get_certificate_id(environment, microservice)
    if not ok:
        return False

    ok, certificate_detail = get_certificate_detail(certificate_id)
    if not ok:
        return False

    ok, remaining_days = determine_expiration_date(certificate_detail)
    if not ok:
        return False

    if remaining_days < REMAINING_DAY_THRESHOLD:
        domain_name = certificate_detail.get("common_name")
        logger.warning(
            f"Certificate for {domain_name} "
            f"is about to expire in {remaining_days} days!"
        )
        if filename is None:
            filename = f"{environment}_{CERTIFICATE_VALIDITY_FILE}"
        with open(filename, "a") as f:
            f.write(f"{domain_name},{remaining_days}\n")

    return True


def main():
    github_event = os.getenv("GITHUB_EVENT_NAME")
    if github_event == "schedule" or github_event == "push":
        environments = ["test", "production"]
    else:
        environments = [os.getenv("ENVIRONMENT", "").lower()]

    for env in environments:
        ok, services = get_active_microservices(env)
        if not ok:
            logger.error(f"Failed to get secrets for {env} environment!")
            return 1

        for service in services:
            evaluate_expiration(env, service)

    return 0


if __name__ == "__main__":
    exit(main())
