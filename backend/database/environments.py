"""
PromptAegis Environment & Isolation Router.
Provides physical database isolation per environment, environment registry management,
and credential-to-environment authentication mapping.
"""
import contextvars
import json
import os
import shutil
import sqlite3
import time
from typing import Any, Dict, List, Optional

import config

# Context variable for trusted internal execution (defaults to research_benchmark for experiment scripts)
_current_environment: contextvars.ContextVar[str] = contextvars.ContextVar(
    "current_environment", default="research_benchmark"
)

# Canonical Environments Definition
DEFAULT_ENVIRONMENTS = [
    {
        "id": "research_benchmark",
        "name": "Research Benchmark",
        "type": "research_benchmark",
        "description": "Simulated CRM, order, and email tools for paper reproducibility and scientific evaluation",
        "db_filename": "gateway_benchmark.db",
        "allow_seed": True,
        "allow_external_runtime": True,
        "status": "active",
        "created_at": 1790000000.0,
    },
    {
        "id": "local_dev",
        "name": "Local Dev Sandbox",
        "type": "local_dev",
        "description": "Isolated developer scratchpad for custom principals, capabilities, and policies",
        "db_filename": "gateway_local_dev.db",
        "allow_seed": False,
        "allow_external_runtime": True,
        "status": "active",
        "created_at": 1790900000.0,
    },
    {
        "id": "connected_application",
        "name": "Connected Application",
        "type": "connected_application",
        "description": "Live application gateway mediating external agent tool proposals",
        "db_filename": "gateway_connected.db",
        "allow_seed": False,
        "allow_external_runtime": True,
        "status": "active",
        "created_at": 1790900000.0,
    },
]

# Default API Credentials (Environment-Bound Tokens)
DEFAULT_CREDENTIALS = {
    "pa_benchmark_test_key": {
        "environment_id": "research_benchmark",
        "name": "Research Benchmark Evaluation Key",
        "allowed_roles": ["benchmark_runner", "admin"],
        "created_at": 1790000000.0,
    },
    "pa_local_dev_key": {
        "environment_id": "local_dev",
        "name": "Local Dev Sandbox Key",
        "allowed_roles": ["developer", "admin"],
        "created_at": 1790900000.0,
    },
    "pa_live_connected_app_key": {
        "environment_id": "connected_application",
        "name": "Connected Application Integration Key",
        "allowed_roles": ["application_gateway", "admin"],
        "created_at": 1790900000.0,
    },
}


from contextlib import contextmanager

def get_current_environment() -> str:
    """Return the currently bound environment ID for this execution context."""
    return _current_environment.get()


def set_current_environment(env_id: str) -> contextvars.Token:
    """Explicitly set the environment context for the current execution."""
    return _current_environment.set(env_id)


def reset_current_environment(token: contextvars.Token) -> None:
    """Reset environment context to previous value using token."""
    _current_environment.reset(token)


@contextmanager
def environment_scope(env_id: str):
    """
    Context manager guaranteeing strict request-scoped execution and token reset.
    Guarantees no worker thread context survives request completion.
    """
    token = _current_environment.set(env_id)
    try:
        yield env_id
    finally:
        _current_environment.reset(token)


class EnvironmentRegistry:
    """Manages registered environments and database path resolution."""

    @classmethod
    def get_registry_path(cls) -> str:
        return getattr(
            config,
            "ENVIRONMENTS_REGISTRY_PATH",
            os.path.join(config.BASE_DIR, "database", "environments.json"),
        )

    @classmethod
    def init_registry(cls) -> None:
        path = cls.get_registry_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as fp:
                json.dump(DEFAULT_ENVIRONMENTS, fp, indent=2)

    @classmethod
    def list_environments(cls, sanitize: bool = True) -> List[Dict[str, Any]]:
        cls.init_registry()
        try:
            with open(cls.get_registry_path(), "r", encoding="utf-8") as fp:
                envs = json.load(fp)
        except Exception:
            envs = DEFAULT_ENVIRONMENTS

        if sanitize:
            # Strip internal database filenames, connection details, and filesystem locations
            return [
                {
                    "id": e["id"],
                    "name": e["name"],
                    "type": e.get("type", "custom"),
                    "description": e.get("description", ""),
                    "allow_seed": e.get("allow_seed", False),
                    "allow_external_runtime": e.get("allow_external_runtime", True),
                    "status": e.get("status", "active"),
                }
                for e in envs
            ]
        return envs

    @classmethod
    def get_environment(cls, env_id: str, sanitize: bool = False) -> Optional[Dict[str, Any]]:
        envs = cls.list_environments(sanitize=False)
        for e in envs:
            if e["id"] == env_id:
                if sanitize:
                    return {
                        "id": e["id"],
                        "name": e["name"],
                        "type": e.get("type", "custom"),
                        "description": e.get("description", ""),
                        "allow_seed": e.get("allow_seed", False),
                        "allow_external_runtime": e.get("allow_external_runtime", True),
                        "status": e.get("status", "active"),
                    }
                return e
        return None

    @classmethod
    def register_environment(
        cls, env_id: str, name: str, env_type: str, description: str = ""
    ) -> Dict[str, Any]:
        cls.init_registry()
        envs = cls.list_environments(sanitize=False)
        for e in envs:
            if e["id"] == env_id:
                raise ValueError(f"Environment '{env_id}' already exists.")

        new_entry = {
            "id": env_id,
            "name": name,
            "type": env_type,
            "description": description,
            "db_filename": f"gateway_{env_id}.db",
            "allow_seed": False,
            "allow_external_runtime": True,
            "status": "active",
            "created_at": time.time(),
        }
        envs.append(new_entry)
        with open(cls.get_registry_path(), "w", encoding="utf-8") as fp:
            json.dump(envs, fp, indent=2)
        return new_entry

    @classmethod
    def resolve_db_path(cls, env_id: str) -> str:
        """Resolve authoritative absolute SQLite database path for an environment."""
        env = cls.get_environment(env_id, sanitize=False)
        db_dir = os.path.join(config.BASE_DIR, "database")

        if env_id == "research_benchmark" or (env and env["type"] == "research_benchmark"):
            return getattr(config, "BENCHMARK_DB_PATH", os.path.join(db_dir, "gateway_benchmark.db"))
        elif env_id == "local_dev" or (env and env["type"] == "local_dev"):
            return getattr(config, "LOCAL_DEV_DB_PATH", os.path.join(db_dir, "gateway_local_dev.db"))
        elif env_id == "connected_application" or (env and env["type"] == "connected_application"):
            return getattr(config, "CONNECTED_APP_DB_PATH", os.path.join(db_dir, "gateway_connected.db"))
        elif env:
            return os.path.join(db_dir, env.get("db_filename", f"gateway_{env_id}.db"))
        else:
            raise ValueError(f"Unknown environment ID '{env_id}'. Cannot resolve database path.")


class CredentialManager:
    """Manages API credentials, environment-to-credential authentication, and secret loading."""

    @classmethod
    def get_credentials_path(cls) -> str:
        return getattr(
            config,
            "CREDENTIALS_REGISTRY_PATH",
            os.path.join(config.BASE_DIR, "database", "credentials.json"),
        )

    @classmethod
    def init_credentials(cls) -> None:
        path = cls.get_credentials_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as fp:
                json.dump(DEFAULT_CREDENTIALS, fp, indent=2)

    @classmethod
    def get_credential(cls, token: str) -> Optional[Dict[str, Any]]:
        if not token or not isinstance(token, str):
            return None

        # 1. Environment Variable Overrides (for live deployments/containers)
        env_connected = os.getenv("PROMPTAEGIS_CONNECTED_APP_KEY")
        if env_connected and token == env_connected:
            return {
                "environment_id": "connected_application",
                "name": "Live Connected Application Key (from ENV)",
                "allowed_roles": ["application_gateway", "admin"],
                "created_at": 1790900000.0,
                "is_test_credential": False,
            }

        env_local = os.getenv("PROMPTAEGIS_LOCAL_DEV_KEY")
        if env_local and token == env_local:
            return {
                "environment_id": "local_dev",
                "name": "Local Dev Sandbox Key (from ENV)",
                "allowed_roles": ["developer", "admin"],
                "created_at": 1790900000.0,
                "is_test_credential": False,
            }

        env_bench = os.getenv("PROMPTAEGIS_BENCHMARK_KEY")
        if env_bench and token == env_bench:
            return {
                "environment_id": "research_benchmark",
                "name": "Research Benchmark Evaluation Key (from ENV)",
                "allowed_roles": ["benchmark_runner", "admin"],
                "created_at": 1790000000.0,
                "is_test_credential": True,
            }

        # 2. Persisted File Registry
        cls.init_credentials()
        try:
            with open(cls.get_credentials_path(), "r", encoding="utf-8") as fp:
                creds = json.load(fp)
            if token in creds:
                rec = dict(creds[token])
                rec.setdefault("is_test_credential", token in DEFAULT_CREDENTIALS)
                return rec
        except Exception:
            pass

        # 3. Deterministic Seed Fallback for Dev/Testing
        if token in DEFAULT_CREDENTIALS:
            rec = dict(DEFAULT_CREDENTIALS[token])
            rec["is_test_credential"] = True
            return rec

        return None

    @classmethod
    def create_credential(
        cls, environment_id: str, name: str, allowed_roles: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        cls.init_credentials()
        with open(cls.get_credentials_path(), "r", encoding="utf-8") as fp:
            creds = json.load(fp)

        import secrets
        # Cryptographically secure live token generator
        token = f"pa_live_{secrets.token_hex(24)}"
        record = {
            "environment_id": environment_id,
            "name": name,
            "allowed_roles": allowed_roles or ["application_gateway"],
            "created_at": time.time(),
            "is_test_credential": False,
        }
        creds[token] = record
        with open(cls.get_credentials_path(), "w", encoding="utf-8") as fp:
            json.dump(creds, fp, indent=2)

        return {"token": token, **record}

