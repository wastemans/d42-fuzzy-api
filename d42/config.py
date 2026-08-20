"""Load Device42 config from config.ini or environment."""

from __future__ import annotations

import configparser
import os
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Config:
    """Runtime configuration for Device42 API calls."""

    url: str
    client_key: str
    secret_key: str
    verify_ssl: bool = True
    limit: int = 50

    @property
    def base_url(self) -> str:
        return self.url.rstrip("/")


def _as_bool(value: str | bool, default: bool = True) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _find_config_path() -> Path | None:
    candidates = [
        Path.cwd() / "config.ini",
        PROJECT_ROOT / "config.ini",
    ]
    for path in candidates:
        if path.is_file():
            return path
    return None


def _is_placeholder(value: str) -> bool:
    return (not value) or value.upper().startswith("YOUR_")


def load_config() -> Config:
    """
    Load config from environment (preferred) then config.ini.

    Env vars:
      D42_URL, D42_CLIENT_KEY, D42_SECRET_KEY, D42_VERIFY_SSL, D42_LIMIT

    D42_CLIENT_SECRET / ini client_secret are accepted as aliases for secret_key.
    """
    parser = configparser.ConfigParser()
    config_path = _find_config_path()
    if config_path:
        parser.read(config_path)

    section = "device42" if parser.has_section("device42") else None
    search = "search" if parser.has_section("search") else None

    def ini(section_name: str | None, key: str, default: str = "") -> str:
        if not section_name or not parser.has_option(section_name, key):
            return default
        return parser.get(section_name, key).strip()

    url = os.environ.get("D42_URL") or ini(section, "url")
    client_key = os.environ.get("D42_CLIENT_KEY") or ini(section, "client_key")
    secret_key = (
        os.environ.get("D42_SECRET_KEY")
        or os.environ.get("D42_CLIENT_SECRET")
        or ini(section, "secret_key")
        or ini(section, "client_secret")
    )
    verify_raw = os.environ.get("D42_VERIFY_SSL") or ini(section, "verify_ssl", "true")
    limit_raw = os.environ.get("D42_LIMIT") or ini(search, "limit", "50")

    missing = [name for name, value in [
        ("url / D42_URL", url),
        ("client_key / D42_CLIENT_KEY", client_key),
        ("secret_key / D42_SECRET_KEY", secret_key),
    ] if _is_placeholder(value)]
    if missing:
        raise SystemExit(
            "Missing Device42 config: "
            + ", ".join(missing)
            + f". Copy {PROJECT_ROOT / 'config.ini.example'} to config.ini "
            "or set D42_URL / D42_CLIENT_KEY / D42_SECRET_KEY."
        )

    try:
        limit = max(1, int(limit_raw))
    except ValueError:
        limit = 50

    return Config(
        url=url,
        client_key=client_key,
        secret_key=secret_key,
        verify_ssl=_as_bool(verify_raw, True),
        limit=limit,
    )
