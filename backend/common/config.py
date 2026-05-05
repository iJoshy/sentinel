"""Configuration helpers for Sentinel backend."""

from __future__ import annotations

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional in some runtime contexts
    load_dotenv = None


if load_dotenv is not None:
    # Load repo-level .env for local scripts; harmless in AWS Lambda if absent.
    _repo_env = Path(__file__).resolve().parents[2] / ".env"
    load_dotenv(_repo_env, override=False)


def is_local() -> bool:
    """Return True when no production database backend is configured."""
    return not (
        os.getenv("AURORA_CLUSTER_ARN", "").strip()
        and os.getenv("AURORA_SECRET_ARN", "").strip()
    ) and not gcp_postgres_configured()


def sqlite_path() -> str:
    """Absolute path to the local SQLite database file."""
    default = str(Path(__file__).resolve().parents[2] / "sentinel.db")
    return os.getenv("LOCAL_DB_PATH", default)


def get_db_path() -> str:
    """Backward-compatible alias: returns Aurora database name or local SQLite path."""
    if is_local():
        return sqlite_path()
    return aurora_database()


def aurora_cluster_arn() -> str:
    return os.getenv("AURORA_CLUSTER_ARN", "").strip()


def aurora_secret_arn() -> str:
    return os.getenv("AURORA_SECRET_ARN", "").strip()


def aurora_database() -> str:
    return (
        os.getenv("AURORA_DATABASE", "").strip()
        or os.getenv("DB_NAME", "").strip()
        or "sentinel"
    )


def aurora_region() -> str:
    return (
        os.getenv("AURORA_REGION", "").strip()
        or os.getenv("DEFAULT_AWS_REGION", "").strip()
        or os.getenv("AWS_REGION", "").strip()
        or "eu-west-1"
    )


def use_bedrock() -> bool:
    return os.getenv("USE_BEDROCK", "false").lower() == "true"


def bedrock_region() -> str:
    return os.getenv("BEDROCK_REGION", os.getenv("DEFAULT_AWS_REGION", "eu-west-1"))


def clerk_secret_key() -> str:
    return os.getenv("CLERK_SECRET_KEY", "")


def use_openrouter() -> bool:
    return os.getenv("USE_OPEN_ROUTER", "false").lower() == "true"


def openrouter_api_key() -> str:
    return os.getenv("OPENROUTER_API_KEY", "")


def openrouter_model() -> str:
    return os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini")


def openrouter_base_url() -> str:
    return os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")


def use_vertex_ai() -> bool:
    return os.getenv("USE_VERTEX_AI", "false").lower() == "true"


def vertex_ai_project_id() -> str:
    return (
        os.getenv("GCP_PROJECT_ID", "").strip()
        or os.getenv("GOOGLE_CLOUD_PROJECT", "").strip()
    )


def vertex_ai_location() -> str:
    return (
        os.getenv("GCP_LOCATION", "").strip()
        or os.getenv("GCP_REGION", "").strip()
        or "us-central1"
    )


def vertex_ai_model() -> str:
    return (
        os.getenv("VERTEX_AI_MODEL", "").strip()
        or os.getenv("GEMINI_MODEL", "").strip()
        or "gemini-2.5-flash"
    )


def gcp_postgres_configured() -> bool:
    return bool(
        os.getenv("DATABASE_URL", "").strip()
        or os.getenv("GCP_CLOUDSQL_CONNECTION_NAME", "").strip()
    )


def gcp_db_name() -> str:
    return os.getenv("GCP_DB_NAME", os.getenv("DB_NAME", "sentinel")).strip() or "sentinel"


def gcp_db_user() -> str:
    return os.getenv("GCP_DB_USER", "sentinel").strip() or "sentinel"


def gcp_db_password() -> str:
    return os.getenv("GCP_DB_PASSWORD", "").strip()


def gcp_cloudsql_connection_name() -> str:
    return os.getenv("GCP_CLOUDSQL_CONNECTION_NAME", "").strip()


def gcp_db_host() -> str:
    return os.getenv("GCP_DB_HOST", "127.0.0.1").strip() or "127.0.0.1"


def gcp_db_port() -> int:
    try:
        return int(os.getenv("GCP_DB_PORT", "5432"))
    except ValueError:
        return 5432


def pubsub_jobs_topic() -> str:
    return os.getenv("PUBSUB_JOBS_TOPIC", "").strip()


def active_model() -> str:
    """Return the model identifier for whichever LLM backend is active.

    - USE_OPEN_ROUTER=true  → OPENROUTER_MODEL (default: openai/gpt-4o-mini)
    - USE_BEDROCK=true      → BEDROCK_MODEL_ID  (default: eu.amazon.nova-pro-v1:0)
    - USE_VERTEX_AI=true    → VERTEX_AI_MODEL   (default: gemini-2.5-flash)
    """
    if use_vertex_ai():
        return vertex_ai_model()
    if use_openrouter():
        return openrouter_model()
    return os.getenv("BEDROCK_MODEL_ID", "eu.amazon.nova-pro-v1:0")


def reminder_interval_seconds() -> int:
    """Interval in seconds between background reminder checks."""
    try:
        return int(os.getenv("REMINDER_INTERVAL_SECONDS", "60"))
    except ValueError:
        return 60
