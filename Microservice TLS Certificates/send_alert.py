import os
import subprocess
import logging
from pathlib import Path


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

logger = logging.getLogger(__name__)


def get_alert_message(file_path: str) -> str:
    """
    Reads a file containing lines like 'domain,days'
    and returns a formatted alert message.
    """
    messages = []
    path = Path(file_path)

    if not path.exists():
        logger.debug("File %s does not exist, skipping.", file_path)
        return ""

    logger.info("Reading certificate validity file: %s", file_path)
    with path.open("r") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) == 2:
                domain = parts[0].strip()
                days = parts[1].strip()
                messages.append(f"Certificate for {domain} expires in {days} days")
                logger.debug("Found certificate: %s expires in %s days", domain, days)

    return "\n".join(messages)


def build_slack_payload(slack_title: str, slack_text: str) -> dict:
    """
    Build Slack fields.
    """
    slack_fields = {}
    slack_fields["SLACK_TITLE"] = slack_title
    slack_fields["SLACK_TEXT"] = slack_text

    return slack_fields


def send_slack_alert(slack_fields: dict):
    """
    Run the Slack notifier container with the given environment fields.
    """
    logger.info("Preparing to send Slack alert...")

    env = os.environ.copy()
    env.update({
        "SLACK_USER_NAME": "Platform Ops Automation",
        "SLACK_ICON_EMOJI": ":siren-light:",
        "SLACK_COLOR": "danger",
        "SLACK_TITLE_LINK": os.getenv("BUILD_URL", "")
    })
    env.update(slack_fields)

    required_env_vars = [
        "SLACK_NOTIFIER_CONTAINER",
        "NOTIFICATION_SLACK_CHANNEL_WEBHOOK",
        "NOTIFICATION_SLACK_CHANNEL_NAME",
    ]

    missing_vars = [var for var in required_env_vars if not os.getenv(var)]

    if missing_vars:
        for var in missing_vars:
            logger.error("%s is not set, cannot send alert.", var)
        raise RuntimeError(f"Missing required environment variables: {', '.join(missing_vars)}")

    container = os.getenv("SLACK_NOTIFIER_CONTAINER")
    channel_webhook = os.getenv("NOTIFICATION_SLACK_CHANNEL_WEBHOOK")
    channel_name = os.getenv("NOTIFICATION_SLACK_CHANNEL_NAME")

    logger.debug("Running Slack notifier container: %s", container)
    subprocess.run(
        [
            "docker", "run", "-i", "--rm",
            "--env", "SLACK_WEBHOOK_URL=" + channel_webhook,
            "--env", "SLACK_CHANNEL=" + channel_name,
            "--env", "SLACK_USER_NAME=" + env.get("SLACK_USER_NAME"),
            "--env", "SLACK_ICON_EMOJI=" + env.get("SLACK_ICON_EMOJI", ""),
            "--env", "SLACK_TITLE=" + env.get("SLACK_TITLE", ""),
            "--env", "SLACK_TITLE_LINK=" + env.get("SLACK_TITLE_LINK", ""),
            "--env", "SLACK_TEXT=" + env.get("SLACK_TEXT", ""),
            "--env", "SLACK_FIELD1_TITLE=" + env.get("SLACK_FIELD1_TITLE", ""),
            "--env", "SLACK_FIELD1_VALUE=" + env.get("SLACK_FIELD1_VALUE", ""),
            "--env", "SLACK_FIELD2_TITLE=" + env.get("SLACK_FIELD2_TITLE", ""),
            "--env", "SLACK_FIELD2_VALUE=" + env.get("SLACK_FIELD2_VALUE", ""),
            container,
        ],
        check=True,
        env=env,
    )
    logger.info("Slack alert sent successfully.")


def send_simple_alert(slack_text: str):
    slack_fields = {}
    slack_fields.update(build_slack_payload("", slack_text))
    send_slack_alert(slack_fields)


def create_artifact(test_file: str, prod_file: str, artifact_dir: str = "expired_certificates") -> str:
    """
    Create a GitHub Actions artifact directory containing test and production
    certificate files (if they exist). Each file only contains domain names.
    """
    artifact_path = Path(artifact_dir)
    artifact_path.mkdir(parents=True, exist_ok=True)
    logger.info("Creating artifact directory: %s", artifact_path)

    if Path(test_file).exists():
        test_out = artifact_path / "test"
        with open(test_file, "r") as src, open(test_out, "w") as dst:
            for line in src:
                parts = line.strip().split(",")
                if len(parts) == 2:
                    dst.write(parts[0].strip() + "\n")
        logger.info("Created test artifact: %s", test_out)

    if Path(prod_file).exists():
        prod_out = artifact_path / "production"
        with open(prod_file, "r") as src, open(prod_out, "w") as dst:
            for line in src:
                parts = line.strip().split(",")
                if len(parts) == 2:
                    dst.write(parts[0].strip() + "\n")
        logger.info("Created production artifact: %s", prod_out)

    return str(artifact_path)

def main():
    test_file = "test_certificate_validity"
    prod_file = "production_certificate_validity"

    send_alert_flag = False
    slack_fields = {}

    if Path(test_file).exists():
        logger.info("Test certificate file found: %s", test_file)
        send_alert_flag = True
        slack_fields["SLACK_FIELD1_TITLE"] = "Test environment"
        slack_fields["SLACK_FIELD1_VALUE"] = get_alert_message(test_file)

    if Path(prod_file).exists():
        logger.info("Production certificate file found: %s", prod_file)
        send_alert_flag = True
        slack_fields["SLACK_FIELD2_TITLE"] = "Production environment"
        slack_fields["SLACK_FIELD2_VALUE"] = get_alert_message(prod_file)

    if send_alert_flag:
        logger.info("Alert Slack for expired certificates")
    else:
        logger.info("No certificate files found, skipping alert.")

    if send_alert_flag:
        logger.warning("Found expired certificates! Sending alert...")
        github_output = os.getenv("GITHUB_OUTPUT")

        if github_output:
            with open(github_output, "a") as f:
                if Path(test_file).exists():
                    f.write("expired_certificates_test=true\n")
                    logger.debug("Wrote expired_certificates_test=true to GITHUB_OUTPUT")
                if Path(prod_file).exists():
                    f.write("expired_certificates_production=true\n")
                    logger.debug("Wrote expired_certificates_production=true to GITHUB_OUTPUT")

        # create artifact folder for upload
        artifact_dir = create_artifact(test_file, prod_file)
        logger.info("Created artifact folder: %s", artifact_dir)

        slack_title = "Go to this link to approve the renewal automation"
        slack_text = "ZeroSSL certificates are about to expire"
        slack_fields.update(build_slack_payload(slack_title, slack_text))

        send_slack_alert(slack_fields)
    else:
        logger.info("No alerts to send.")



if __name__ == "__main__":
    main()
