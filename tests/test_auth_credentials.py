from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from api.auth import get_authenticated_environment
from database.environments import CredentialManager, DEFAULT_CREDENTIALS


def test_live_credential_is_not_a_deterministic_development_default(monkeypatch):
    monkeypatch.delenv("PROMPTAEGIS_CONNECTED_APP_KEY", raising=False)
    monkeypatch.setenv("PROMPTAEGIS_ALLOW_TEST_CREDENTIALS", "1")
    assert "pa_live_connected_app_key" not in DEFAULT_CREDENTIALS
    assert CredentialManager.get_credential("pa_live_connected_app_key") is None


@pytest.mark.parametrize("token", ["pa_benchmark_test_key", "pa_local_dev_key"])
def test_test_credentials_require_explicit_local_opt_in(monkeypatch, token):
    monkeypatch.delenv("PROMPTAEGIS_BENCHMARK_KEY", raising=False)
    monkeypatch.delenv("PROMPTAEGIS_LOCAL_DEV_KEY", raising=False)
    monkeypatch.delenv("PROMPTAEGIS_ALLOW_TEST_CREDENTIALS", raising=False)
    assert CredentialManager.get_credential(token) is None

    monkeypatch.setenv("PROMPTAEGIS_ALLOW_TEST_CREDENTIALS", "1")
    record = CredentialManager.get_credential(token)
    assert record is not None
    assert record["is_test_credential"] is True


def test_connected_application_requires_high_entropy_environment_key(monkeypatch):
    monkeypatch.setenv("PROMPTAEGIS_CONNECTED_APP_KEY", "short-test-key")
    assert CredentialManager.get_credential("short-test-key") is None
    strong = "pa_live_test_only_0123456789abcdef0123456789abcdef"
    monkeypatch.setenv("PROMPTAEGIS_CONNECTED_APP_KEY", strong)
    record = CredentialManager.get_credential(strong)
    assert record is not None
    assert record["environment_id"] == "connected_application"
    assert record["is_test_credential"] is False


def test_test_credential_cannot_authenticate_connected_application(monkeypatch):
    monkeypatch.delenv("PROMPTAEGIS_CONNECTED_APP_KEY", raising=False)
    monkeypatch.setenv("PROMPTAEGIS_ALLOW_TEST_CREDENTIALS", "1")
    with pytest.raises(HTTPException) as exc:
        get_authenticated_environment(
            x_promptaegis_key="pa_benchmark_test_key",
            x_promptaegis_environment="connected_application",
            authorization=None,
        )
    assert exc.value.status_code == 403
