# tests/test_get_zerossl_certificate.py
import os
import json
import pytest
from datetime import datetime, timedelta, timezone

import get_zerossl_certificate as gzc


@pytest.fixture(autouse=True)
def set_env(monkeypatch):
    monkeypatch.setenv("ZEROSSL_API_KEY", "fake-api-key")


# ---------------------------
# get_certificate_detail
# ---------------------------
def test_get_certificate_detail_success(monkeypatch):
    class DummyResponse:
        def raise_for_status(self): pass
        def json(self): return {"id": "cert123"}
    monkeypatch.setattr(gzc.requests, "get", lambda *a, **kw: DummyResponse())

    ok, data = gzc.get_certificate_detail("cert123")
    assert ok is True
    assert data == {"id": "cert123"}


def test_get_certificate_detail_failure(monkeypatch):
    class DummyResponse:
        def raise_for_status(self): raise gzc.requests.RequestException("boom")
    monkeypatch.setattr(gzc.requests, "get", lambda *a, **kw: DummyResponse())

    ok, data = gzc.get_certificate_detail("cert123", retries=1)
    assert ok is False
    assert data is None


def test_get_certificate_detail_no_api_key(monkeypatch):
    monkeypatch.delenv("ZEROSSL_API_KEY", raising=False)
    with pytest.raises(RuntimeError):
        gzc.get_certificate_detail("cert123")


# ---------------------------
# get_active_microservices
# ---------------------------
def test_get_active_microservices_success(monkeypatch):
    class DummyPaginator:
        def paginate(self): 
            return [
                {"SecretList": [
                    {"Name": "/test/services/api/zerossl_certificate"},
                    {"Name": "/test/services/web/zerossl_certificate"}
                ]}
            ]
    dummy_client = type("C", (), {"get_paginator": lambda self, _: DummyPaginator()})
    monkeypatch.setattr(gzc.boto3, "client", lambda *_: dummy_client())

    ok, services = gzc.get_active_microservices("test")
    assert ok is True
    assert services == ["api", "web"]


def test_get_active_microservices_none_found(monkeypatch, caplog):
    class DummyPaginator:
        def paginate(self): return [{"SecretList": []}]
    dummy_client = type("C", (), {"get_paginator": lambda self, _: DummyPaginator()})
    monkeypatch.setattr(gzc.boto3, "client", lambda *_: dummy_client())

    ok, services = gzc.get_active_microservices("test")
    assert ok is False
    assert services is None
    assert "No secrets found" in caplog.text


def test_get_active_microservices_client_error(monkeypatch):
    from botocore.exceptions import ClientError
    dummy_client = type("C", (), {"get_paginator": lambda self, _: (_ for _ in ()).throw(ClientError({"Error": {}}, "op"))})
    monkeypatch.setattr(gzc.boto3, "client", lambda *_: dummy_client())

    ok, services = gzc.get_active_microservices("test")
    assert ok is False
    assert services is None


# ---------------------------
# get_certificate_id
# ---------------------------
def test_get_certificate_id_success(monkeypatch):
    secret_value = {"id": "cert123"}
    dummy_client = type("C", (), {
        "get_secret_value": lambda self, SecretId: {"SecretString": json.dumps(secret_value)}
    })
    monkeypatch.setattr(gzc.boto3, "client", lambda *_: dummy_client())

    ok, cert_id = gzc.get_certificate_id("test", "api")
    assert ok is True
    assert cert_id == "cert123"


def test_get_certificate_id_missing_secretstring(monkeypatch):
    dummy_client = type("C", (), {
        "get_secret_value": lambda self, SecretId: {"SecretString": None}
    })
    monkeypatch.setattr(gzc.boto3, "client", lambda *_: dummy_client())

    ok, cert_id = gzc.get_certificate_id("test", "api")
    assert ok is False
    assert cert_id is None


def test_get_certificate_id_missing_id(monkeypatch):
    secret_value = {"wrongkey": "abc"}
    dummy_client = type("C", (), {
        "get_secret_value": lambda self, SecretId: {"SecretString": json.dumps(secret_value)}
    })
    monkeypatch.setattr(gzc.boto3, "client", lambda *_: dummy_client())

    ok, cert_id = gzc.get_certificate_id("test", "api")
    assert ok is False
    assert cert_id is None


def test_get_certificate_id_client_error(monkeypatch):
    from botocore.exceptions import ClientError
    dummy_client = type("C", (), {
        "get_secret_value": lambda self, SecretId: (_ for _ in ()).throw(ClientError({"Error": {}}, "op"))
    })
    monkeypatch.setattr(gzc.boto3, "client", lambda *_: dummy_client())

    ok, cert_id = gzc.get_certificate_id("test", "api")
    assert ok is False
    assert cert_id is None


# ---------------------------
# determine_expiration_date
# ---------------------------
def test_determine_expiration_valid(monkeypatch):
    expires = (datetime.now(timezone.utc) + timedelta(days=10)).strftime("%Y-%m-%d %H:%M:%S")
    cert = {"status": "issued", "expires": expires, "common_name": "example.com"}
    ok, days = gzc.determine_expiration_date(cert)
    assert ok is True
    assert days >= 9


def test_determine_expiration_expired():
    expires = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    cert = {"status": "issued", "expires": expires, "common_name": "expired.com"}
    ok, days = gzc.determine_expiration_date(cert)
    assert ok is False
    assert days is None


def test_determine_expiration_not_issued():
    cert = {"status": "pending", "common_name": "abc.com"}
    ok, days = gzc.determine_expiration_date(cert)
    assert ok is False
    assert days is None


# ---------------------------
# evaluate_expiration
# ---------------------------
def test_evaluate_expiration_valid(monkeypatch, tmp_path):
    # Mock get_certificate_id
    monkeypatch.setattr(gzc, "get_certificate_id", lambda e, m: (True, "cert123"))
    # Mock get_certificate_detail
    cert = {
        "status": "issued",
        "expires": (datetime.now(timezone.utc) + timedelta(days=5)).strftime("%Y-%m-%d %H:%M:%S"),
        "common_name": "test.com",
    }
    monkeypatch.setattr(gzc, "get_certificate_detail", lambda cid: (True, cert))
    monkeypatch.setattr(gzc, "determine_expiration_date", lambda detail: (True, 5))

    filename = tmp_path / "validity.txt"
    ok = gzc.evaluate_expiration("test", "api", filename=str(filename))
    assert ok is True
    text = filename.read_text()
    assert "test.com,5" in text


def test_evaluate_expiration_all_fail(monkeypatch):
    monkeypatch.setattr(gzc, "get_certificate_id", lambda e, m: (False, None))
    ok = gzc.evaluate_expiration("test", "api")
    assert ok is False


# ---------------------------
# main
# ---------------------------
def test_main_success(monkeypatch):
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setattr(gzc, "get_active_microservices", lambda e: (True, ["api"]))
    monkeypatch.setattr(gzc, "evaluate_expiration", lambda e, m: True)

    rc = gzc.main()
    assert rc == 0


def test_main_failure(monkeypatch):
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setattr(gzc, "get_active_microservices", lambda e: (False, None))
    rc = gzc.main()
    assert rc == 1
