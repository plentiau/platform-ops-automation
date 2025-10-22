# tests/test_send_alert.py
import os
import subprocess
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

import send_alert


def test_get_alert_message_file_not_exist(tmp_path):
    file_path = tmp_path / "missing.txt"
    result = send_alert.get_alert_message(str(file_path))
    assert result == ""


def test_get_alert_message_valid(tmp_path):
    file_path = tmp_path / "certs.txt"
    file_path.write_text("example.com,10\nanother.com,5\ninvalid_line\n")

    result = send_alert.get_alert_message(str(file_path))
    assert "Certificate for example.com expires in 10 days" in result
    assert "Certificate for another.com expires in 5 days" in result
    assert "invalid_line" not in result


def test_build_slack_payload():
    payload = send_alert.build_slack_payload("title", "text")
    assert payload["SLACK_TITLE"] == "title"
    assert payload["SLACK_TEXT"] == "text"


@patch.dict(os.environ, {}, clear=True)
def test_send_slack_alert_missing_env_vars():
    fields = {"SLACK_TEXT": "test"}
    with pytest.raises(RuntimeError) as excinfo:
        send_alert.send_slack_alert(fields)
    assert "Missing required environment variables" in str(excinfo.value)


@patch.dict(
    os.environ,
    {
        "SLACK_NOTIFIER_CONTAINER": "slack-notifier",
        "NOTIFICATION_SLACK_CHANNEL_WEBHOOK": "http://webhook",
        "NOTIFICATION_SLACK_CHANNEL_NAME": "alerts",
    },
    clear=True,
)
@patch("subprocess.run")
def test_send_slack_alert_success(mock_run):
    fields = {"SLACK_TEXT": "hello"}
    send_alert.send_slack_alert(fields)
    mock_run.assert_called_once()
    args, kwargs = mock_run.call_args
    assert "docker" in args[0][0]
    assert kwargs["check"] is True
    assert isinstance(kwargs["env"], dict)


@patch("send_alert.send_slack_alert")
def test_send_simple_alert(mock_alert):
    send_alert.send_simple_alert("hello world")
    mock_alert.assert_called_once()
    called_fields = mock_alert.call_args[0][0]
    assert called_fields["SLACK_TEXT"] == "hello world"


def test_create_artifact_creates_files(tmp_path):
    test_file = tmp_path / "test.txt"
    prod_file = tmp_path / "prod.txt"

    test_file.write_text("example.com,20\n")
    prod_file.write_text("prod.com,15\n")

    artifact_dir = tmp_path / "artifact"
    result = send_alert.create_artifact(str(test_file), str(prod_file), str(artifact_dir))

    assert Path(result).exists()
    test_artifact = Path(result) / "test"
    prod_artifact = Path(result) / "production"

    assert test_artifact.read_text().strip() == "example.com"
    assert prod_artifact.read_text().strip() == "prod.com"


def test_create_artifact_skips_missing_files(tmp_path):
    test_file = tmp_path / "missing_test.txt"
    prod_file = tmp_path / "missing_prod.txt"

    artifact_dir = tmp_path / "artifact"
    result = send_alert.create_artifact(str(test_file), str(prod_file), str(artifact_dir))
    assert Path(result).exists()
    # no files created
    assert not (Path(result) / "test").exists()
    assert not (Path(result) / "production").exists()


@patch("send_alert.create_artifact", return_value="artifact_dir")
@patch("send_alert.send_slack_alert")
@patch("send_alert.get_alert_message", side_effect=["test msg", "prod msg"])
@patch.dict(
    os.environ,
    {
        "SLACK_NOTIFIER_CONTAINER": "slack-notifier",
        "NOTIFICATION_SLACK_CHANNEL_WEBHOOK": "http://webhook",
        "NOTIFICATION_SLACK_CHANNEL_NAME": "alerts",
    },
    clear=True,
)
def test_main_with_files(mock_msg, mock_slack, mock_artifact, tmp_path):
    test_file = tmp_path / "test_certificate_validity"
    prod_file = tmp_path / "production_certificate_validity"
    test_file.write_text("test.com,5\n")
    prod_file.write_text("prod.com,3\n")

    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        send_alert.main()
    finally:
        os.chdir(cwd)

    mock_slack.assert_called_once()
    args = mock_slack.call_args[0][0]
    assert "SLACK_FIELD1_VALUE" in args
    assert "SLACK_FIELD2_VALUE" in args
    assert "ZeroSSL certificates are about to expire" in args["SLACK_TEXT"]


def test_main_no_files(tmp_path):
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        # No files created
        send_alert.main()  # should not raise
    finally:
        os.chdir(cwd)
