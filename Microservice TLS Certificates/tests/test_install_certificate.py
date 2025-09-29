import os
import json
import requests
import builtins
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open
from botocore.exceptions import ClientError

import install_certificate as ic


# --------------------------
# download_certificate tests
# --------------------------

@patch("install_certificate.requests.get")
def test_download_certificate_success(mock_get):
    mock_get.return_value.json.return_value = {"certificate.crt": "crt", "ca_bundle.crt": "ca"}
    mock_get.return_value.raise_for_status = lambda: None

    with patch.dict(os.environ, {"ZEROSSL_API_KEY": "fake"}):
        result = ic.download_certificate("cert123")

    assert result["certificate.crt"] == "crt"
    assert result["ca_bundle.crt"] == "ca"
    mock_get.assert_called_once()


@patch("install_certificate.requests.get", side_effect=requests.RequestException("network error"))
def test_download_certificate_fail(mock_get):
    with patch.dict(os.environ, {"ZEROSSL_API_KEY": "fake"}):
        # set sleep_seconds=0 so the test doesn't wait between retries
        result = ic.download_certificate("cert123", retries=2, sleep_seconds=0)

    assert result is None
    # called once per attempt: retries=2 -> 2 calls
    assert mock_get.call_count == 2


def test_download_certificate_no_env():
    if "ZEROSSL_API_KEY" in os.environ:
        del os.environ["ZEROSSL_API_KEY"]

    with pytest.raises(RuntimeError, match="ZEROSSL_API_KEY"):
        ic.download_certificate("cert123")


# --------------------------
# update_secrets_manager tests
# --------------------------

@patch("install_certificate.boto3.client")
def test_update_secrets_manager_success(mock_boto):
    mock_client = MagicMock()
    mock_boto.return_value = mock_client

    result = ic.update_secrets_manager("secret1", "crt", "ca", "key", "id")
    assert result is True
    mock_client.update_secret.assert_called_once()
    args, kwargs = mock_client.update_secret.call_args
    secret_data = json.loads(kwargs["SecretString"])
    assert secret_data["certificate.crt"] == "crt"


@patch("install_certificate.boto3.client")
def test_update_secrets_manager_failure(mock_boto):
    mock_client = MagicMock()
    # construct a proper ClientError to be raised by update_secret
    error_response = {"Error": {"Code": "AccessDenied", "Message": "boom"}}
    mock_client.update_secret.side_effect = ClientError(error_response, "UpdateSecret")
    mock_boto.return_value = mock_client

    result = ic.update_secrets_manager("secret1", "crt", "ca", "key", "id")

    assert result is False
    mock_client.update_secret.assert_called_once()
    mock_boto.assert_called_once_with("secretsmanager")


# --------------------------
# start_instance_refresh tests
# --------------------------

@patch("install_certificate.boto3.client")
def test_start_instance_refresh_success(mock_boto):
    mock_client = MagicMock()
    mock_client.start_instance_refresh.return_value = {"InstanceRefreshId": "123"}
    mock_client.describe_instance_refreshes.side_effect = [
        {"InstanceRefreshes": [{"Status": "InProgress"}]},
        {"InstanceRefreshes": [{"Status": "Successful"}]},
    ]
    mock_boto.return_value = mock_client

    result = ic.start_instance_refresh("Test", "asg1")
    assert result is True


@patch("install_certificate.boto3.client")
def test_start_instance_refresh_failure(mock_boto):
    mock_client = MagicMock()
    mock_client.start_instance_refresh.side_effect = Exception("bad")
    mock_boto.return_value = mock_client

    result = ic.start_instance_refresh("Test", "asg1")
    assert result is False


@patch("install_certificate.boto3.client")
def test_start_instance_refresh_cancelled(mock_boto):
    mock_client = MagicMock()
    mock_client.start_instance_refresh.return_value = {"InstanceRefreshId": "123"}
    mock_client.describe_instance_refreshes.return_value = {
        "InstanceRefreshes": [{"Status": "Cancelled"}]
    }
    mock_boto.return_value = mock_client

    result = ic.start_instance_refresh("Test", "asg1")
    assert result is False


# --------------------------
# main() tests
# --------------------------

@patch("install_certificate.send_simple_alert")
@patch("install_certificate.download_certificate")
@patch("install_certificate.update_secrets_manager")
@patch("install_certificate.start_instance_refresh")
def test_main_success(mock_refresh, mock_update, mock_download, mock_alert, tmp_path, monkeypatch):
    # Setup fake environment
    monkeypatch.setenv("ENVIRONMENT", "Test")
    monkeypatch.setenv("ZEROSSL_EMAIL", "user@test.com")

    # Fake cert dir structure
    test_dir = tmp_path / "issued_certificates" / "test" / "service.example.com"
    test_dir.mkdir(parents=True)
    (test_dir / "id").write_text("cert123")
    (test_dir / "private.key").write_text("PRIVATEKEY")

    monkeypatch.chdir(tmp_path)

    # Mock functions
    mock_download.return_value = {"certificate.crt": "crt", "ca_bundle.crt": "ca"}
    mock_update.return_value = True
    mock_refresh.return_value = True

    # Fake ASG mapping
    configs_dir = tmp_path / "configs"
    configs_dir.mkdir()
    (configs_dir / "asg-mappings.json").write_text(json.dumps({"Test": {"service": "asg1"}}))

    result = ic.main()
    assert result == 0
    mock_alert.assert_called_with("Successfully rotated expired certificates!")


@patch("install_certificate.send_simple_alert")
def test_main_missing_env(mock_alert, monkeypatch):
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.setenv("ZEROSSL_EMAIL", "x")

    with pytest.raises(RuntimeError, match="ENVIRONMENT"):
        ic.main()
    mock_alert.assert_called_once()
