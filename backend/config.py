from pathlib import Path
from typing import Any

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

CONFIG_FILE = Path(__file__).parent.parent / "config.yaml"


def _load_yaml() -> dict[str, Any]:
    if CONFIG_FILE.exists():
        return yaml.safe_load(CONFIG_FILE.read_text()) or {}
    return {}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", env_file_encoding="utf-8")

    s3_endpoint: str = "https://ax5csdwebcis.compat.objectstorage.us-phoenix-1.oci.customer-oci.com"
    s3_bucket: str = "us-phoenix-1.stellarcyber.cloud-datasink-bucket"
    s3_region: str = "us-phoenix-1"
    org_id: str = "25f6245e120343bfb9eb46e412b7c583"
    tenant_id: str = "df66914f9f254b2a9f673a5a04a6c8f5"
    local_sync_path: str = "./data"
    db_path: str = "./soc.duckdb"
    parquet_base: str = ""  # if empty, defaults to db_path sibling dir "parquet/"
    indexes: list[str] = Field(
        default=[
            "adr",
            "syslog",
            "wineventlog",
            "users",
            "assets",
            "maltrace",
            "cloudtrail",
            "scan",
            "ser",
            "ade",
            "audit",
        ]
    )
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    openrouter_api_key: str = ""
    nl_model: str = ""  # override free model selection; e.g. "meta-llama/llama-3.1-8b-instruct:free"

    @classmethod
    def load(cls) -> "Settings":
        yaml_data = _load_yaml()
        return cls(**yaml_data)


_settings_cache: Settings | None = None


def get_settings() -> Settings:
    global _settings_cache
    if _settings_cache is None:
        _settings_cache = Settings.load()
    return _settings_cache


def save_settings(data: dict[str, Any]) -> None:
    global _settings_cache
    current = _load_yaml()
    current.update(data)
    CONFIG_FILE.write_text(yaml.dump(current, default_flow_style=False))
    _settings_cache = None  # invalida caché tras guardar
