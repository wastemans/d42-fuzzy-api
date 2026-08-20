"""Device42 REST + DOQL client (Token Auth)."""

from __future__ import annotations

import re
import time
from typing import Any

import requests
import urllib3

from .config import Config


class Device42Error(Exception):
    """Raised when a Device42 API call fails."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


_IP_LIKE = re.compile(
    r"^(?:\d{1,3}(?:\.\d{1,3}){0,3}|\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})$"
)


def looks_like_ip(term: str) -> bool:
    """Return True if term looks like an IPv4 address or prefix."""
    return bool(_IP_LIKE.match(term.strip()))


def sql_literal(value: str) -> str:
    """Escape a value for safe inclusion in a DOQL string literal."""
    return value.replace("'", "''")


def like_literal(value: str) -> str:
    """Escape a value for use inside a DOQL LIKE pattern (also escapes % and _)."""
    return (
        sql_literal(value)
        .replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )


class Device42Client:
    """
    Device42 client using API Client Token Auth.

    Flow (Resources → Secrets → API Clients):
      1. POST /tauth/1.0/token with JSON
         {"client_key": "...", "secret_key": "..."}
      2. Use Authorization: Bearer <token> on API calls
    """

    _REFRESH_SKEW_SECONDS = 60

    def __init__(self, config: Config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})
        self.session.verify = config.verify_ssl
        if not config.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self._access_token: str | None = None
        self._token_expires_at: float = 0.0
        self._authenticate()

    def _url(self, path: str) -> str:
        return f"{self.config.base_url}{path}"

    def _authenticate(self) -> None:
        """Exchange client_key + secret_key for a Bearer token via Basic Auth."""
        try:
            # This Device42 build expects HTTP Basic(client_key, secret_key)
            # on /tauth/1.0/token/ (JSON body returns 401 Invalid API token request).
            response = self.session.post(
                self._url("/tauth/1.0/token/"),
                auth=(self.config.client_key, self.config.secret_key),
                headers={"Accept": "application/json"},
                timeout=30,
            )
        except requests.RequestException as exc:
            raise Device42Error(f"Token request failed: {exc}") from exc

        if response.status_code >= 400:
            raise Device42Error(
                f"Token auth failed HTTP {response.status_code}: {response.text[:500]}",
                status_code=response.status_code,
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise Device42Error(f"Invalid token JSON: {response.text[:300]}") from exc

        token = (
            payload.get("token")
            or payload.get("access_token")
            or payload.get("accessToken")
        )
        if not token:
            raise Device42Error(f"No token in auth response: {payload}")

        self._access_token = str(token)
        # Device42 returns ttl in minutes on this appliance.
        expires_in = payload.get("expires_in") or payload.get("expiresIn")
        ttl_minutes = payload.get("ttl")
        try:
            if expires_in is not None:
                ttl_seconds = int(expires_in)
            elif ttl_minutes is not None:
                ttl_seconds = int(ttl_minutes) * 60
            else:
                ttl_seconds = 600
        except (TypeError, ValueError):
            ttl_seconds = 600
        self._token_expires_at = time.time() + max(60, ttl_seconds - self._REFRESH_SKEW_SECONDS)
        self.session.headers["Authorization"] = f"Bearer {self._access_token}"
        # Do not leave Basic auth on the session for later API calls.
        self.session.auth = None

    def _ensure_token(self) -> None:
        if not self._access_token or time.time() >= self._token_expires_at:
            self._authenticate()

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        _retried: bool = False,
    ) -> Any:
        self._ensure_token()
        try:
            response = self.session.request(
                method,
                self._url(path),
                params=params,
                data=data,
                timeout=120,
            )
        except requests.RequestException as exc:
            raise Device42Error(f"Request failed: {exc}") from exc

        if response.status_code in {401, 403} and not _retried:
            self._authenticate()
            return self._request(
                method, path, params=params, data=data, _retried=True
            )

        if response.status_code >= 400:
            raise Device42Error(
                f"HTTP {response.status_code}: {response.text[:500]}",
                status_code=response.status_code,
            )

        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError as exc:
            raise Device42Error(f"Invalid JSON: {response.text[:300]}") from exc

    def doql(self, query: str) -> list[dict[str, Any]]:
        """Run a DOQL SELECT and return JSON rows."""
        result = self._request(
            "POST",
            "/services/data/v1.0/query/",
            data={"query": query, "output_type": "json"},
        )
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            for key in ("rows", "data", "result"):
                if isinstance(result.get(key), list):
                    return result[key]
        raise Device42Error(f"Unexpected DOQL response shape: {type(result)}")

    def search_devices_by_name(self, term: str, limit: int | None = None) -> list[dict]:
        """Substring search on device name via REST."""
        limit = limit or self.config.limit
        payload = self._request(
            "GET",
            "/api/1.0/devices/",
            params={"name": term, "limit": limit, "offset": 0},
        )
        return _list_from_payload(payload, "Devices", "devices")

    def search_ips(self, term: str, limit: int | None = None) -> list[dict]:
        """Search IP addresses (partial match supported by Device42)."""
        limit = limit or self.config.limit
        payload = self._request(
            "GET",
            "/api/1.0/ips/",
            params={"ip": term, "limit": limit, "offset": 0},
        )
        return _list_from_payload(payload, "ips")

    def search_assets_by_name(self, term: str, limit: int | None = None) -> list[dict]:
        """Substring search on asset name via REST."""
        limit = limit or self.config.limit
        payload = self._request(
            "GET",
            "/api/1.0/assets/",
            params={"name": term, "limit": limit, "offset": 0},
        )
        return _list_from_payload(payload, "assets")

    def get_device(self, device_id: int | str) -> dict:
        """Fetch a single device by id."""
        return self._request("GET", f"/api/1.0/devices/{device_id}/")


def _list_from_payload(payload: Any, *keys: str) -> list[dict]:
    """
    Normalise Device42 list payloads.

    Shapes seen in the wild:
      {"devices": [...]}
      {"Devices": {"devices": [...], "total_count": N}}
      {"Devices": [...]}
      [...]
    """
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    if not isinstance(payload, dict):
        return []

    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return [row for row in value if isinstance(row, dict)]
        if isinstance(value, dict):
            nested = value.get(key.lower()) or value.get("devices") or value.get("assets") or value.get("ips")
            if isinstance(nested, list):
                return [row for row in nested if isinstance(row, dict)]
            for nested_key in ("devices", "assets", "ips", "Objects", "objects"):
                nested = value.get(nested_key)
                if isinstance(nested, list):
                    return [row for row in nested if isinstance(row, dict)]
    return []
