import os
import requests
import logging
import boto3
import time
import re

from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from botocore.exceptions import ClientError

from get_zerossl_certificate import get_certificate_detail

# Setup logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
numeric_level = getattr(logging, LOG_LEVEL, logging.INFO)
logging.basicConfig(
    level=numeric_level,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

logger = logging.getLogger(__name__)

ZEROSSL_URL = "https://api.zerossl.com"


def create_csr(common_name: str, email: str):
    """
    Generate CSR body formatted for ZeroSSL API (no headers/footers).
    Also return the PEM-formatted private key.
    
    Returns:
        tuple (csr_body, private_key_pem)
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "AU"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "New South Wales"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Sydney"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Plenti"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ])

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(key, hashes.SHA256())
    )

    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    # API requires only base64 body, no BEGIN/END lines
    csr_body = "".join(
        line.strip() for line in csr_pem.splitlines() if not line.startswith("-----")
    )

    private_key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # PKCS#1
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    return csr_body, private_key_pem


def request_certificate(certificate_domain: str, certificate_csr: str, retries: int = 3, sleep_seconds: int = 5):
    """
    Request a ZeroSSL certificate for the given domain, retrying on failure.

    Args:
        certificate_domain: Domain name for the certificate.
        certificate_csr: CSR for the certificate.
        retries (int): Number of retries on failure (default 3).
        sleep_seconds (int): Seconds to wait between retries (default 5).

    Returns:
        dict: JSON response from ZeroSSL API if status is 'draft', None otherwise.
    """
    access_key = os.getenv("ZEROSSL_API_KEY")
    if not access_key:
        raise RuntimeError("ZEROSSL_API_KEY environment variable is not set")

    zerossl_email = os.getenv("ZEROSSL_EMAIL")
    if not zerossl_email:
        raise RuntimeError("ZEROSSL_EMAIL environment variable is not set")

    data = {
        "certificate_domains": certificate_domain,
        "certificate_validity_days": 90,
        "certificate_csr": certificate_csr,
        "certificate_type": "dv_ssl",
        "strict_domains": 1,
    }

    url = f"{ZEROSSL_URL}/certificates"

    for attempt in range(1, retries + 1):
        try:
            response = requests.post(url, params={"access_key": access_key}, data=data, timeout=30)
            response.raise_for_status()
            json_response = response.json()

            if json_response.get("error"):
                logger.error("ZeroSSL API error: %s", json_response.get("error"))
                return None

            if json_response.get("status") == "draft":
                return json_response

            logger.warning(
                "Certificate request for %s returned unexpected status: %s",
                certificate_domain,
                json_response.get("status"),
            )
            return None

        except requests.RequestException as e:
            logger.exception(
                "Attempt %d failed to create certificate for %s: %s", attempt, certificate_domain, e
            )
            if attempt < retries:
                logger.info("Retrying in %d seconds...", sleep_seconds)
                time.sleep(sleep_seconds)
            else:
                logger.error("All retries failed for certificate request for %s", certificate_domain)
                return None
    

def update_route53(env_name: str, json_response: dict):
    """
    Add CNAME validation records to Route53 for the given environment.

    Args:
        env_name (str): Must be "Test" or "Production"
        json_response (dict): ZeroSSL certificate creation response JSON
    """
    route53 = boto3.client("route53")

    # Hosted zone IDs must be set in environment
    if env_name == "Test":
        hosted_zone_id = os.getenv("PLENTIAU_TEST_HOSTED_ZONE_ID")
    elif env_name == "Production":
        hosted_zone_id = os.getenv("PLENTIAU_PRODUCTION_HOSTED_ZONE_ID")
    else:
        raise ValueError("env_name must be 'Test' or 'Production'")

    if not hosted_zone_id:
        raise RuntimeError(f"Hosted zone ID not set for {env_name}")

    other_methods = json_response.get("validation", {}).get("other_methods", {})
    if not other_methods:
        logger.warning("No 'other_methods' validation found in response.")
        return False

    changes = []
    for domain, validation in other_methods.items():
        cname_name = validation.get("cname_validation_p1")
        cname_value = validation.get("cname_validation_p2")

        if cname_name and cname_value:
            logger.info("Adding CNAME validation for %s -> %s", cname_name, cname_value)
            changes.append({
                "Action": "UPSERT",
                "ResourceRecordSet": {
                    "Name": cname_name,
                    "Type": "CNAME",
                    "TTL": 100,
                    "ResourceRecords": [{"Value": cname_value}],
                },
            })

    if not changes:
        logger.warning("No CNAME validation entries found in ZeroSSL response.")
        return False

    # Apply changes safely
    try:
        route53.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch={"Changes": changes},
        )
    except ClientError as e:
        logger.error("Failed to apply Route53 changes: %s", e, exc_info=True)
        return False

    logger.info("CNAME records successfully added to Route53 zone %s", hosted_zone_id)
    return True


def clean_route53(environment: str, certificate_id: str) -> bool:
    """
    Remove old CNAME records on Route53 for the given certificate ID,
    keeping only the current validation CNAME record.

    Deletes records matching the pattern "_<alphanumeric>.current_domain".
    """
    route53 = boto3.client("route53")

    # Hosted zone IDs must be set in environment
    if environment == "Test":
        hosted_zone_id = os.getenv("PLENTIAU_TEST_HOSTED_ZONE_ID")
    elif environment == "Production":
        hosted_zone_id = os.getenv("PLENTIAU_PRODUCTION_HOSTED_ZONE_ID")
    else:
        raise ValueError("environment must be 'Test' or 'Production'")

    if not hosted_zone_id:
        raise RuntimeError(f"Hosted zone ID not set for {environment}")

    ok, cert_details = get_certificate_detail(certificate_id)
    if not ok:
        return False

    other_methods = cert_details.get("validation", {}).get("other_methods")
    if not other_methods:
        logger.warning("No 'other_methods' validation found in response.")
        return False

    # Current validation record
    cname_name = None
    cname_value = None
    for _, validation in other_methods.items():
        cname_name = validation.get("cname_validation_p1").lower().rstrip(".")
        cname_value = validation.get("cname_validation_p2")
        if cname_name and cname_value:
            break

    if not cname_name or not cname_value:
        logger.warning("No valid CNAME record found in cert details.")
        return False

    current_domain = cert_details.get("common_name").rstrip(".")

    logger.info("Current validation CNAME: %s -> %s", cname_name, cname_value)

    # List all CNAMEs in hosted zone and delete the old ones
    paginator = route53.get_paginator("list_resource_record_sets")
    to_delete = []
    for page in paginator.paginate(HostedZoneId=hosted_zone_id):
        for record in page["ResourceRecordSets"]:
            if record["Type"] != "CNAME":
                continue

            record_name = record["Name"].rstrip(".")
            record_values = [v["Value"].rstrip(".") for v in record.get("ResourceRecords", [])]

            # Match only "_<token>.current_domain"
            if re.match(r"^_[A-Za-z0-9]+\." + re.escape(current_domain) + r"$", record_name):
                if record_name != cname_name:
                    for val in record_values:
                        to_delete.append((record_name, val))

    if not to_delete:
        logger.info("No old CNAME records to delete.")
        return True

    for name, val in to_delete:
        try:
            route53.change_resource_record_sets(
                HostedZoneId=hosted_zone_id,
                ChangeBatch={
                    "Changes": [
                        {
                            "Action": "DELETE",
                            "ResourceRecordSet": {
                                "Name": name,
                                "Type": "CNAME",
                                "TTL": 100,
                                "ResourceRecords": [{"Value": val}],
                            }
                        }
                    ]
                },
            )
            logger.info("Deleted old CNAME %s -> %s", name, val)
        except Exception as e:
            logger.error("Failed to delete record %s -> %s: %s", name, val, e)
            return False

    return True


def verify_domain(certificate_id: str):
    """
    Verify domain ownership for a certificate via ZeroSSL API.

    Will retry under certain error conditions or if validation is still pending.

    Args:
        certificate_id (str): ZeroSSL certificate ID.

    Returns:
        dict: JSON response if success, None otherwise.
    """
    access_key = os.getenv("ZEROSSL_API_KEY")
    if not access_key:
        raise RuntimeError("ZEROSSL_API_KEY environment variable is not set")

    url = f"{ZEROSSL_URL}/certificates/{certificate_id}/challenges"
    deadline = datetime.now(timezone.utc) + timedelta(minutes=5)

    while datetime.now(timezone.utc) < deadline:
        try:
            response = requests.post(
                url,
                params={"access_key": access_key},
                data={"validation_method": "CNAME_CSR_HASH"},
                timeout=30
            )
            response.raise_for_status()
            json_response = response.json()
            error = json_response.get("error")

            logger.debug("Certificate detail: %s", json_response)

            # --- Case 1: pending validation ---
            if (
                json_response.get("id") == certificate_id
                and json_response.get("status") == "pending_validation"
            ):
                logger.info("Certificate %s still pending validation, retrying...", certificate_id)
                time.sleep(10)
                continue

            # --- Case 2: domain control validation failed -> retry ---
            if (
                json_response.get("success") == False
                and error.get("code") == 0 and
                error.get("type") == "domain_control_validation_failed"
            ):
                logger.info("Domain control validation failed, retrying...")
                time.sleep(10)
                continue

            # --- Case 3: certificate not ready to validate, fetch certificate detail ---
            if (
                json_response.get("success") == False
                and error.get("code") == 2831
                and error.get("type") == "certificate_not_ready_to_validate"
            ):
                logger.info("Certificate not ready to validate, checking status...")
                ok, cert_details = get_certificate_detail(certificate_id)

                if not ok:
                    logger.warning("Failed to get certificate ID")
                    time.sleep(10)
                    continue

                logger.debug("Certificate detail: %s", cert_details)

                if cert_details and cert_details.get("status") == "issued":
                    logger.info("Certificate %s has been issued!", certificate_id)
                    return cert_details
    
                time.sleep(10)
                continue

            # --- Other errors ---
            logger.error("ZeroSSL verify-domain error: %s", json_response.get("error"))
            return None

        except requests.RequestException as e:
            logger.error("Failed to verify domain for certificate %s: %s", certificate_id, e)
            time.sleep(10)

    logger.error("Timeout while verifying domain for certificate %s", certificate_id)
    return None


def main():
    test_file = Path("expired_certificates/test")
    prod_file = Path("expired_certificates/production")
    
    issued_certificate_test_folder = Path("issued_certificates/test")
    issued_certificate_production_folder = Path("issued_certificates/production")

    environment = os.getenv("ENVIRONMENT")
    if not environment:
        raise RuntimeError("ENVIRONMENT environment variable is not set")

    zerossl_email = os.getenv("ZEROSSL_EMAIL")
    if not zerossl_email:
        raise RuntimeError("ZEROSSL_EMAIL environment variable is not set")
    
    if environment == "Test":
        expired_env_file = test_file
        issued_env_folder = issued_certificate_test_folder
    elif environment == "Production":
        expired_env_file = prod_file
        issued_env_folder = issued_certificate_production_folder
    else:
        raise RuntimeError("Undefined value for ENVIRONMENT environment variable: %s", environment)

    if expired_env_file.exists():
        logger.info("%s certificate file found: %s", environment, expired_env_file)
        with expired_env_file.open("r") as f:
            for line in f:
                # Loop through domains
                certificate_domain = line.strip()
                logger.info("-------------------------------")
                logger.info("Renewing certificate for domain: %s", certificate_domain)

                if not certificate_domain:
                    continue

                logger.info("Requesting certificate...")
                certificate_csr, private_key = create_csr(certificate_domain, zerossl_email)
                json_response = request_certificate(certificate_domain, certificate_csr)
                # Check if request to create a new certificate is success
                if not json_response:
                    logger.error("❌ Failed to request certificate or status is not draft!")
                    return 1  # exit immediately with error
                else:
                    logger.info("Successfully requested draft certificate!")

                    logger.info("Updating Route53 records for domain validation...")

                    update_result = update_route53(environment, json_response)
                    # Check if domain validation is success with Route53
                    if not update_result:
                        logging.error("❌ Failed to update Route53 record!")
                        return 1  # exit immediately with error
                    else:
                        logger.info("Successfully updated Route53 record for domain validation!")

                        logger.info("Verifying domain...")

                        certificate_id = json_response.get("id")

                        verify_result = verify_domain(certificate_id)
                        # Check if domain verify is success
                        if not verify_result:
                            logging.error("❌ Failed to verify domain!")
                            return 1  # exit immediately with error
                        else:
                            logger.info("✅ Successfully verified domain!")

                            logger.info("Cleaning old Route53 CNAME record...")

                            clean_result = clean_route53(environment, certificate_id)
                            # Check if records cleaning is success
                            if not clean_result:
                                logging.warning("❌ Failed to clean old CNAME records!")

                            logger.info("Exporting certificate ID and private key...")
                            parent_folder = f"{issued_env_folder}/{certificate_domain}"
                            os.makedirs(parent_folder, exist_ok=True)
                            # Write ID
                            with open(os.path.join(parent_folder, "id"), "a") as f:
                                f.write(f"{certificate_id}\n")
                            # Write private key
                            with open(os.path.join(parent_folder, "private.key"), "a") as f:
                                f.write(f"{private_key}\n")
    else:
        logger.info("No certificate file found for %s environment.", environment)

    return 0


if __name__ == "__main__":
    exit(main())
