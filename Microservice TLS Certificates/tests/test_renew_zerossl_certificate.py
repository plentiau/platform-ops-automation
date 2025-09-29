import os
import io
import builtins
import pytest
import types
import requests
from unittest.mock import patch, MagicMock, mock_open

import renew_zerossl_certificate as rzc


# ---------------------------
# Fixtures
# ---------------------------
@pytest.fixture(autouse=True)
def clear_env(monkeypatch):
    """Ensure clean environment for each test."""
    monkeypatch.delenv("ZEROSSL_API_KEY", raising=False)
    monkeypatch.delenv("ZEROSSL_EMAIL", raising=False)
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.delenv("PLENTIAU_TEST_HOSTED_ZONE_ID", raising=False)
    monkeypatch.delenv("PLENTIAU_PRODUCTION_HOSTED_ZONE_ID", raising=False)


# ---------------------------
# create_csr
# ---------------------------
def test_create_csr_returns_valid(monkeypatch):
    csr, key = rzc.create_csr("example.com", "me@example.com")
    assert "-----BEGIN" not in csr
    assert "PRIVATE KEY" in key


# ---------------------------
# request_certificate
# ---------------------------
def test_request_certificate_success(monkeypatch):
    monkeypatch.setenv("ZEROSSL_API_KEY", "fake-key")
    monkeypatch.setenv("ZEROSSL_EMAIL", "me@example.com")

    fake_resp = MagicMock()
    fake_resp.json.return_value = {"status": "draft", "id": "cert123"}
    fake_resp.raise_for_status.return_value = None

    with patch("requests.post", return_value=fake_resp) as mock_post:
        out = rzc.request_certificate("example.com", "csrbody")
        assert out["id"] == "cert123"
        mock_post.assert_called_once()


def test_request_certificate_error_json(monkeypatch):
    monkeypatch.setenv("ZEROSSL_API_KEY", "fake-key")
    monkeypatch.setenv("ZEROSSL_EMAIL", "me@example.com")

    fake_resp = MagicMock()
    fake_resp.json.return_value = {"error": {"message": "bad"}}
    fake_resp.raise_for_status.return_value = None

    with patch("requests.post", return_value=fake_resp):
        assert rzc.request_certificate("example.com", "csrbody") is None


def test_request_certificate_retries(monkeypatch):
    monkeypatch.setenv("ZEROSSL_API_KEY", "fake-key")
    monkeypatch.setenv("ZEROSSL_EMAIL", "me@example.com")

    # Patch the requests.post used in the module under test and raise a requests.RequestException
    with patch("renew_zerossl_certificate.requests.post", side_effect=requests.RequestException("boom")) as mock_post:
        out = rzc.request_certificate("example.com", "csrbody", retries=2, sleep_seconds=0)
        assert out is None
        # ensure it retried the expected number of times
        assert mock_post.call_count == 2


# ---------------------------
# update_route53
# ---------------------------
def test_update_route53_success(monkeypatch):
    monkeypatch.setenv("PLENTIAU_TEST_HOSTED_ZONE_ID", "Z111")

    fake_client = MagicMock()
    with patch("boto3.client", return_value=fake_client):
        resp = {
            "validation": {"other_methods": {
                "example.com": {"cname_validation_p1": "_abc.example.com",
                                "cname_validation_p2": "token.example.com"}
            }}
        }
        ok = rzc.update_route53("Test", resp)
        assert ok is True
        fake_client.change_resource_record_sets.assert_called_once()


def test_update_route53_no_methods(monkeypatch):
    monkeypatch.setenv("PLENTIAU_TEST_HOSTED_ZONE_ID", "Z111")
    fake_client = MagicMock()
    with patch("boto3.client", return_value=fake_client):
        ok = rzc.update_route53("Test", {"validation": {}})
        assert ok is False


def test_update_route53_invalid_env():
    with pytest.raises(ValueError):
        rzc.update_route53("Staging", {})


# ---------------------------
# clean_route53
# ---------------------------
def test_clean_route53_deletes(monkeypatch):
    monkeypatch.setenv("PLENTIAU_TEST_HOSTED_ZONE_ID", "Z111")

    cert_details = {
        "common_name": "example.com",
        "validation": {"other_methods": {
            "example.com": {
                "cname_validation_p1": "_abc.example.com",
                "cname_validation_p2": "token.example.com",
            }
        }},
    }
    with patch("renew_zerossl_certificate.get_certificate_detail", return_value=(True, cert_details)):
        fake_client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "ResourceRecordSets": [
                {"Type": "CNAME", "Name": "_old.example.com.",
                 "ResourceRecords": [{"Value": "token.old"}]}
            ]
        }]
        fake_client.get_paginator.return_value = paginator
        with patch("boto3.client", return_value=fake_client):
            ok = rzc.clean_route53("Test", "cert123")
            assert ok is True
            fake_client.change_resource_record_sets.assert_called()


# ---------------------------
# verify_domain
# ---------------------------
def test_verify_domain_issued(monkeypatch):
    monkeypatch.setenv("ZEROSSL_API_KEY", "fake-key")

    # First response: not ready
    not_ready = {"success": False, "error": {"code": 2831, "type": "certificate_not_ready_to_validate"}}
    issued = {"status": "issued", "id": "cert123"}

    fake_resp = MagicMock()
    fake_resp.json.side_effect = [not_ready]
    fake_resp.raise_for_status.return_value = None

    with patch("requests.post", return_value=fake_resp):
        with patch("renew_zerossl_certificate.get_certificate_detail", return_value=(True, issued)):
            result = rzc.verify_domain("cert123")
            assert result["status"] == "issued"


# ---------------------------
# main()
# ---------------------------
def test_main_env_missing(monkeypatch):
    with patch("renew_zerossl_certificate.send_simple_alert") as mock_alert:
        with pytest.raises(RuntimeError):
            rzc.main()
        mock_alert.assert_called()


def test_main_no_file(monkeypatch, tmp_path):
    monkeypatch.setenv("ENVIRONMENT", "Test")
    monkeypatch.setenv("ZEROSSL_EMAIL", "me@example.com")

    # Create empty expired_certificates/test dir
    base = tmp_path / "expired_certificates"
    (base / "test").parent.mkdir(parents=True, exist_ok=True)

    with patch("renew_zerossl_certificate.Path", side_effect=lambda p: tmp_path / p):
        result = rzc.main()
        assert result == 0
