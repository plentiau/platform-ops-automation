import os
import requests
import logging
import json
import boto3
import time

from botocore.exceptions import ClientError
from pathlib import Path

from send_alert import send_simple_alert


# Setup logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
numeric_level = getattr(logging, LOG_LEVEL, logging.INFO)
logging.basicConfig(
    level=numeric_level,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

logger = logging.getLogger(__name__)

ZEROSSL_URL = "https://api.zerossl.com"

def download_certificate(certificate_id: str, retries: int = 3, sleep_seconds: int = 5):
    """
    Download certificate from ZeroSSL (inline return), retrying on failure.

    Args:
        certificate_id (str): ZeroSSL certificate ID.
        retries (int): Number of retries on failure (default 3).
        sleep_seconds (int): Seconds to wait between retries (default 5).

    Returns:
        dict: JSON response with certificate details if successful, None otherwise.
    """
    access_key = os.getenv("ZEROSSL_API_KEY")
    if not access_key:
        raise RuntimeError("ZEROSSL_API_KEY environment variable is not set")

    url = f"{ZEROSSL_URL}/certificates/{certificate_id}/download/return"

    for attempt in range(1, retries + 1):
        try:
            response = requests.get(url, params={"access_key": access_key}, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            logger.error(
                "Attempt %d failed to download certificate %s: %s", attempt, certificate_id, e
            )
            if attempt < retries:
                logger.info("Retrying in %d seconds...", sleep_seconds)
                time.sleep(sleep_seconds)
            else:
                logger.error("All retries failed for downloading certificate %s", certificate_id)
                return None


def update_secrets_manager(secret_name: str, certificate_crt: str, ca_bundle_crt: str, private_key: str, certificate_id: str) -> bool:
    """
    Update a Secrets Manager secret with certificate, CA bundle, private key, and ID.

    Args:
        secret_name (str): Name of the secret.
        certificate_crt (str): Certificate content.
        ca_bundle_crt (str): CA bundle content.
        private_key (str): Private key content.
        certificate_id (str): Certificate ID.

    Returns:
        bool: True if update succeeded, False otherwise.
    """
    client = boto3.client("secretsmanager")

    secret_value = {
        "certificate.crt": certificate_crt,
        "ca_bundle.crt": ca_bundle_crt,
        "private.key": private_key,
        "id": certificate_id
    }

    try:
        response = client.update_secret(
            SecretId=secret_name,
            SecretString=json.dumps(secret_value)
        )
        logger.info("Secrets Manager updated successfully for %s", secret_name)
        return True
    except ClientError as e:
        logger.error("Failed to update Secrets Manager for %s: %s", secret_name, e)
        return False

def start_instance_refresh(environment: str, asg_name: str) -> bool:
    """
    Start an instance refresh for the ASG corresponding to the given environment and service.
    Always waits until the refresh is completed.

    Args:
        environment (str): "Test" or "Production".
        asg_name (str): ASG name.

    Returns:
        bool: True if refresh succeeded, False otherwise.
    """
    autoscaling = boto3.client("autoscaling")
    try:
        resp = autoscaling.start_instance_refresh(AutoScalingGroupName=asg_name)
        refresh_id = resp["InstanceRefreshId"]
        logger.info(
            "Started instance refresh for ASG: %s (Env: %s, RefreshId: %s)",
            asg_name, environment, refresh_id
        )
    except Exception as e:
        logger.error("Failed to start instance refresh for %s: %s", asg_name, e)
        return False

    # Wait until instance refresh completes
    while True:
        try:
            status_resp = autoscaling.describe_instance_refreshes(
                AutoScalingGroupName=asg_name,
                InstanceRefreshIds=[refresh_id]
            )
            if not status_resp.get("InstanceRefreshes"):
                logger.error("No refresh info returned for %s", asg_name)
                return False

            status = status_resp["InstanceRefreshes"][0]["Status"]
            logger.info("Instance refresh status for %s: %s", asg_name, status)

            if status == "Successful":
                logger.info("Instance refresh is done")
                return True
            elif status in ("Cancelled", "Failed"):
                return False

        except Exception as e:
            logger.error("Error checking refresh status for %s: %s", asg_name, e)
            return False

        time.sleep(30)


def main():
    issued_certificate_test_folder = Path("issued_certificates/test")
    issued_certificate_production_folder = Path("issued_certificates/production")

    environment = os.getenv("ENVIRONMENT")
    if not environment:
        # Notify Slack
        send_simple_alert("Failed to request certificate!")
        raise RuntimeError("ENVIRONMENT environment variable is not set")

    zerossl_email = os.getenv("ZEROSSL_EMAIL")
    if not zerossl_email:
        # Notify Slack
        send_simple_alert("Failed to request certificate!")
        raise RuntimeError("ZEROSSL_EMAIL environment variable is not set")
    
    if environment == "Test":
        issued_env_folder = issued_certificate_test_folder
    elif environment == "Production":
        issued_env_folder = issued_certificate_production_folder
    else:
        # Notify Slack
        send_simple_alert("Failed to request certificate!")
        raise RuntimeError(f"Undefined value for ENVIRONMENT: {environment}")

    for certificate_domain_folder in issued_env_folder.iterdir():
        if not certificate_domain_folder.is_dir():
            continue  # skip non-directory files

        certificate_domain = certificate_domain_folder.name
        id_file = certificate_domain_folder / "id"
        private_key_file = certificate_domain_folder / "private.key"

        # Check if id file exists and ID is valid
        if not id_file.exists():
            logger.error("❌ Missing id file for %s", certificate_domain)
            # Notify Slack
            send_simple_alert(f"Failed to request certificate for {certificate_domain}!")
            return 1
        with id_file.open("r") as f:
            certificate_id = f.readline().strip()
        if not certificate_id:
            logger.error("❌ Invalid certificate ID for %s", certificate_domain)
            # Notify Slack
            send_simple_alert(f"Failed to request certificate for {certificate_domain}!")
            return 1

        # Check if private key file exists and private key is valid
        if not private_key_file.exists():
            logger.error("❌ Missing private key for %s", certificate_domain)
            # Notify Slack
            send_simple_alert(f"Failed to request certificate for {certificate_domain}!")
            return 1
        with private_key_file.open("r") as f:
            private_key = f.read().strip()
        if not private_key:
            logger.error("❌ Invalid private key for %s", certificate_domain)
            # Notify Slack
            send_simple_alert(f"Failed to request certificate for {certificate_domain}!")
            return 1

        logger.info("------------------------------")
        logger.info("Install certificate for domain %s", certificate_domain)

        # Download certificate
        logger.info("Downloading certificate %s...", certificate_id)
        download_result = download_certificate(certificate_id)

        # Check if certificate download success 
        if not download_result:
            logger.error("❌ Failed to download certificate for %s", certificate_domain)
            # Notify Slack
            send_simple_alert(f"Failed to request certificate for {certificate_domain}!")
            return 1
        else:
            logger.info("Successfully downloaded certificate!")

        certificate_crt = download_result.get("certificate.crt", "")
        ca_bundle_crt = download_result.get("ca_bundle.crt", "")

        if not certificate_crt or not ca_bundle_crt:
            logger.error("❌ Missing certificate.crt or ca_bundle.crt for %s", certificate_domain)
            # Notify Slack
            send_simple_alert(f"Failed to request certificate for {certificate_domain}!")
            return 1

        # Update certificate info to Secrets Manager
        logger.info("Updating certificate to Secrets Manager...")
        lowercase_environment = environment.lower()
        service_name = certificate_domain.split(".")[0]
        secret_name = f"/{lowercase_environment}/services/{service_name}/zerossl_certificate"
        
        update_result = update_secrets_manager(secret_name, certificate_crt, ca_bundle_crt, private_key, certificate_id)

        # Check if Secrets Manager update success
        if not update_result:
            logger.warning("❌ Failed to update Secrets Manager")
            # Notify Slack
            send_simple_alert(f"Failed to request certificate for {certificate_domain}!")
            return 1
        else:
            logger.info("✅ Successfully updated Secrets Manager!")
        
    # Refresh ASG
    mapping_file = Path("configs/asg-mappings.json")
    if not mapping_file.exists():
        raise RuntimeError("configs/asg-mappings.json file not found")

    with mapping_file.open() as f:
        mappings = json.load(f)

    env_mapping = mappings.get(environment)
    if not env_mapping:
        raise RuntimeError(f"No mapping found for environment: {environment}")
    asg_groups = {}
    failed_instance_refresh_asg = []
    
    for certificate_domain_folder in issued_env_folder.iterdir():
        if not certificate_domain_folder.is_dir():
            continue  # skip non-directory files
        
        certificate_domain = certificate_domain_folder.name
        service_name = certificate_domain.split(".")[0].strip()

        asg_name = env_mapping.get(service_name)
        if not asg_name:
            logger.error("No ASG mapping found for service: %s in environment %s", service_name, environment)
            # Notify Slack
            send_simple_alert(f"Failed to request certificate for {certificate_domain}!")
            return 1
        asg_groups.setdefault(asg_name, []).append(service_name)

    logger.info("=========Refresh ASGs=========")
    logger.info("==============================")
    for asg in asg_groups:
        logger.info("------------------------------")
        logger.info("Refreshing ASG %s for %s...", asg, ",".join(asg_groups[asg]))
        refresh_result = start_instance_refresh(environment, asg)

        # Check if instance refresh failed
        if not refresh_result:
            logger.error("❌ Failed to start instance refresh for %s", asg)
            failed_instance_refresh_asg.append(asg)
        else:
            logger.info("✅ Successfully refreshed ASG!")
    
    if not failed_instance_refresh_asg:
        # Notify Slack
        send_simple_alert("Successfully rotated expired certificates!")
        return 0
    else:
        failed_asg_string = ",".join(failed_instance_refresh_asg)
        # Notify Slack
        send_simple_alert(f"Failed to perform instance refresh for ASGs: {failed_asg_string}! Please do it manually!")
        return 1


if __name__ == "__main__":
    exit(main())