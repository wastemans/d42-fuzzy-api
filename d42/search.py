"""Fuzzy search Device42 devices and assets by hostname, FQDN/alias, or IP."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .client import Device42Client, Device42Error, looks_like_ip, sql_literal


@dataclass
class InventoryHit:
    """Normalised search hit for a Device or Asset."""

    kind: str  # device | asset
    object_id: int | None
    name: str
    fqdn: str = ""
    ips: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    object_type: str = ""
    os_name: str = ""
    service_level: str = ""
    in_service: str = ""
    last_seen: datetime | None = None
    last_seen_label: str = ""
    sources: list[str] = field(default_factory=list)
    matched_on: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    # Back-compat aliases used by older callers / display helpers
    @property
    def device_id(self) -> int | None:
        return self.object_id if self.kind == "device" else None

    @property
    def device_type(self) -> str:
        return self.object_type

    @property
    def display(self) -> str:
        ip_part = ", ".join(self.ips) if self.ips else "-"
        fqdn_part = self.fqdn or "-"
        seen = self.last_seen_label or "-"
        src = ", ".join(self.sources) if self.sources else "-"
        return (
            f"[{self.kind}] {self.name} | {fqdn_part} | {ip_part} | "
            f"seen {seen} | {src}"
        )


# Keep old name importable
DeviceHit = InventoryHit


def _split_csv(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            if isinstance(item, dict):
                ip = item.get("ip") or item.get("ip_address") or item.get("address")
                if ip:
                    out.append(str(ip))
            elif item:
                out.append(str(item))
        return out
    text = str(value).strip()
    if not text:
        return []
    return [part.strip() for part in text.replace(";", ",").split(",") if part.strip()]


def _parse_dt(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    text = str(value).strip()
    if not text:
        return None
    # Device42 returns ISO timestamps, sometimes with +00:00
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def relative_age(when: datetime | None, *, now: datetime | None = None) -> str:
    """Format a timestamp as '3 days ago' / '2 months ago' / '1 year ago'."""
    if when is None:
        return "unknown"
    now = now or datetime.now(timezone.utc)
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    delta = now - when.astimezone(timezone.utc)
    seconds = int(delta.total_seconds())
    if seconds < 0:
        return "just now"
    minutes = seconds // 60
    hours = minutes // 60
    days = hours // 24
    if seconds < 60:
        return "just now"
    if minutes < 60:
        unit = "minute" if minutes == 1 else "minutes"
        return f"{minutes} {unit} ago"
    if hours < 48:
        unit = "hour" if hours == 1 else "hours"
        return f"{hours} {unit} ago"
    if days < 60:
        unit = "day" if days == 1 else "days"
        return f"{days} {unit} ago"
    months = days // 30
    if months < 24:
        unit = "month" if months == 1 else "months"
        return f"{months} {unit} ago"
    years = days // 365
    unit = "year" if years == 1 else "years"
    return f"{max(1, years)} {unit} ago"


def _score_term(term: str, *candidates: str) -> int:
    needle = term.lower().strip()
    if not needle:
        return 0
    best = 0
    for raw in candidates:
        hay = (raw or "").lower()
        if not hay:
            continue
        if hay == needle:
            best = max(best, 100)
        elif hay.startswith(needle):
            best = max(best, 80)
        elif needle in hay:
            best = max(best, 60)
        else:
            tokens = [t for t in hay.replace(".", " ").split() if t]
            if any(t.startswith(needle) or needle.startswith(t) for t in tokens):
                best = max(best, 40)
    return best


def _pick_fqdn(name: str, aliases: list[str], dns_fqdn: str = "") -> str:
    preferred = [a for a in aliases if "." in a]
    if dns_fqdn and "." in dns_fqdn:
        return dns_fqdn
    if preferred:
        # Prefer longer FQDN-ish aliases
        return sorted(preferred, key=len, reverse=True)[0]
    if "." in (name or ""):
        return name
    return dns_fqdn or ""


def _source_label(row: dict[str, Any]) -> str:
    """Map a discoveryscores row to a short human source label."""
    sub = (row.get("sub_type") or "").strip()
    port = row.get("port")
    scores = row.get("discovery_scores") or {}
    if isinstance(scores, str):
        scores = {}
    score_keys = " ".join(str(k) for k in scores.keys()).lower() if isinstance(scores, dict) else ""

    if "snmp" in score_keys or port == 161:
        return "SNMP"
    if any(k in score_keys for k in ("ping", "icmp")) or "ping" in sub.lower():
        return "ICMP/ping"
    if sub:
        return sub  # e.g. oVirt/Redhat, vmware
    if port == 22:
        return "SSH"
    if port == 443:
        return "HTTPS discovery"
    mode = (row.get("current_mode") or "").strip()
    dtype = (row.get("discovery_type") or "").strip()
    if mode and mode.lower() != "detailed inventory":
        return mode
    if port is not None:
        return f"{dtype or 'discovery'} port {port}".strip()
    return dtype or "discovery"


class AssetSearcher:
    """Search Device42 Devices and Assets by name / alias / IP."""

    def __init__(self, client: Device42Client):
        self.client = client

    def search(self, term: str, limit: int | None = None) -> list[InventoryHit]:
        term = term.strip()
        if not term:
            return []
        limit = limit or self.client.config.limit

        hits: dict[str, InventoryHit] = {}

        try:
            for hit in self._search_devices(term, limit):
                self._merge(hits, hit)
        except Device42Error:
            pass

        try:
            for hit in self._search_assets(term, limit):
                self._merge(hits, hit)
        except Device42Error:
            pass

        if not hits:
            self._rest_fallback(term, limit, hits)

        self._enrich_dns_fqdn(term, hits)
        self._enrich_discovery_sources(hits)

        ranked = sorted(
            hits.values(),
            key=lambda h: (
                0 if h.kind == "device" else 1,
                -_score_term(term, h.name, h.fqdn, *h.aliases, *h.ips),
                h.name.lower(),
            ),
        )
        return ranked[:limit]

    def _search_devices(self, term: str, limit: int) -> list[InventoryHit]:
        lit = sql_literal(term.lower())
        query = f"""
SELECT
  d.device_pk AS object_id,
  d.name AS name,
  d.type AS object_type,
  d.os_name AS os_name,
  d.service_level AS service_level,
  CAST(d.in_service AS text) AS in_service,
  d.last_discovered AS last_discovered,
  d.last_changed AS last_changed,
  string_agg(DISTINCT CAST(i.ip_address AS text), ', ') AS ip_addresses,
  string_agg(DISTINCT a.alias_name, ', ') AS aliases,
  string_agg(DISTINCT CASE WHEN a.preferred THEN a.alias_name END, ', ') AS preferred_aliases
FROM view_device_v2 d
LEFT JOIN view_ipaddress_v1 i ON i.device_fk = d.device_pk
LEFT JOIN view_devicealias_v1 a ON a.device_fk = d.device_pk
WHERE lower(d.name) LIKE '%{lit}%'
   OR lower(COALESCE(a.alias_name, '')) LIKE '%{lit}%'
   OR CAST(i.ip_address AS text) LIKE '%{lit}%'
GROUP BY
  d.device_pk, d.name, d.type, d.os_name, d.service_level, d.in_service,
  d.last_discovered, d.last_changed
ORDER BY d.name
LIMIT {int(limit)}
""".strip()
        try:
            rows = self.client.doql(query)
        except Device42Error:
            # Older schema fallback without aliases / v2
            rows = self.client.doql(self._device_fallback_sql(lit, limit))
        return [self._hit_from_device_row(row, term) for row in rows]

    @staticmethod
    def _device_fallback_sql(lit: str, limit: int) -> str:
        return f"""
SELECT
  d.device_pk AS object_id,
  d.name AS name,
  d.type AS object_type,
  d.os_name AS os_name,
  d.service_level AS service_level,
  CAST(d.in_service AS text) AS in_service,
  d.last_changed AS last_discovered,
  d.last_changed AS last_changed,
  string_agg(DISTINCT CAST(i.ip_address AS text), ', ') AS ip_addresses,
  CAST(NULL AS text) AS aliases,
  CAST(NULL AS text) AS preferred_aliases
FROM view_device_v1 d
LEFT JOIN view_ipaddress_v1 i ON i.device_fk = d.device_pk
WHERE lower(d.name) LIKE '%{lit}%'
   OR CAST(i.ip_address AS text) LIKE '%{lit}%'
GROUP BY d.device_pk, d.name, d.type, d.os_name, d.service_level, d.in_service, d.last_changed
ORDER BY d.name
LIMIT {int(limit)}
""".strip()

    def _search_assets(self, term: str, limit: int) -> list[InventoryHit]:
        lit = sql_literal(term.lower())
        query = f"""
SELECT
  a.asset_pk AS object_id,
  a.name AS name,
  t.name AS object_type,
  CAST(NULL AS text) AS os_name,
  a.service_level_name AS service_level,
  CAST(a.in_service AS text) AS in_service,
  a.last_changed AS last_discovered,
  a.last_changed AS last_changed,
  CAST(NULL AS text) AS ip_addresses,
  CAST(NULL AS text) AS aliases,
  CAST(NULL AS text) AS preferred_aliases
FROM view_asset_v1 a
LEFT JOIN view_assettype_v1 t ON t.assettype_pk = a.assettype_fk
WHERE lower(a.name) LIKE '%{lit}%'
   OR lower(COALESCE(a.serial_no, '')) LIKE '%{lit}%'
   OR lower(COALESCE(a.asset_no, '')) LIKE '%{lit}%'
ORDER BY a.name
LIMIT {int(limit)}
""".strip()
        rows = self.client.doql(query)
        return [self._hit_from_asset_row(row, term) for row in rows]

    def _hit_from_device_row(self, row: dict[str, Any], term: str) -> InventoryHit:
        name = str(row.get("name") or "")
        ips = _split_csv(row.get("ip_addresses"))
        aliases = _split_csv(row.get("aliases"))
        preferred = _split_csv(row.get("preferred_aliases"))
        fqdn = _pick_fqdn(name, preferred or aliases)
        last_seen = _parse_dt(row.get("last_discovered")) or _parse_dt(row.get("last_changed"))
        matched = self._match_labels(term, name=name, fqdn=fqdn, aliases=aliases, ips=ips)
        return InventoryHit(
            kind="device",
            object_id=_as_int(row.get("object_id")),
            name=name,
            fqdn=fqdn,
            ips=ips,
            aliases=aliases,
            object_type=str(row.get("object_type") or ""),
            os_name=str(row.get("os_name") or ""),
            service_level=str(row.get("service_level") or ""),
            in_service=str(row.get("in_service") or ""),
            last_seen=last_seen,
            last_seen_label=relative_age(last_seen),
            matched_on=matched,
            raw=row,
        )

    def _hit_from_asset_row(self, row: dict[str, Any], term: str) -> InventoryHit:
        name = str(row.get("name") or "")
        last_seen = _parse_dt(row.get("last_discovered")) or _parse_dt(row.get("last_changed"))
        matched = self._match_labels(term, name=name)
        return InventoryHit(
            kind="asset",
            object_id=_as_int(row.get("object_id")),
            name=name,
            fqdn="",
            ips=[],
            aliases=[],
            object_type=str(row.get("object_type") or ""),
            service_level=str(row.get("service_level") or ""),
            in_service=str(row.get("in_service") or ""),
            last_seen=last_seen,
            last_seen_label=relative_age(last_seen),
            sources=["asset record"],
            matched_on=matched or ["name"],
            raw=row,
        )

    @staticmethod
    def _match_labels(
        term: str,
        *,
        name: str = "",
        fqdn: str = "",
        aliases: list[str] | None = None,
        ips: list[str] | None = None,
    ) -> list[str]:
        low = term.lower()
        matched: list[str] = []
        if low in name.lower():
            matched.append("name")
        if fqdn and low in fqdn.lower():
            matched.append("fqdn")
        if any(low in a.lower() for a in (aliases or [])):
            matched.append("alias")
        if any(low in ip.lower() for ip in (ips or [])):
            matched.append("ip")
        return matched

    def _enrich_dns_fqdn(self, term: str, hits: dict[str, InventoryHit]) -> None:
        """Fill FQDN from DNS A records when aliases are missing."""
        devices = [h for h in hits.values() if h.kind == "device"]
        if not devices:
            return
        names = sorted({h.name.lower() for h in devices if h.name})
        if not names:
            return
        # Limit IN list size
        names = names[:50]
        in_list = ", ".join(f"'{sql_literal(n)}'" for n in names)
        query = f"""
SELECT lower(r.name) AS short_name, z.name AS zone, CAST(r.content AS text) AS ip
FROM view_dnsrecords_v1 r
JOIN view_dnszone_v1 z ON z.dnszone_pk = r.dnszone_fk
WHERE r.type = 'A'
  AND lower(r.name) IN ({in_list})
""".strip()
        try:
            rows = self.client.doql(query)
        except Device42Error:
            return
        by_short: dict[str, str] = {}
        for row in rows:
            short = str(row.get("short_name") or "")
            zone = str(row.get("zone") or "").lstrip(".")
            if short and zone:
                by_short[short] = f"{short}.{zone}"
        for hit in devices:
            if hit.fqdn:
                continue
            dns_fqdn = by_short.get(hit.name.lower(), "")
            if dns_fqdn:
                hit.fqdn = dns_fqdn
                if term.lower() in dns_fqdn.lower() and "fqdn" not in hit.matched_on:
                    hit.matched_on.append("fqdn")

    def _enrich_discovery_sources(self, hits: dict[str, InventoryHit]) -> None:
        device_ids = [
            h.object_id for h in hits.values()
            if h.kind == "device" and h.object_id is not None
        ]
        if not device_ids:
            return
        id_list = ", ".join(str(i) for i in device_ids[:100])
        query = f"""
SELECT
  device_fk,
  discovery_type,
  sub_type,
  current_mode,
  port,
  port_check,
  discovery_scores,
  status,
  updated
FROM view_discoveryscores_v1
WHERE device_fk IN ({id_list})
ORDER BY updated DESC NULLS LAST
LIMIT 500
""".strip()
        try:
            rows = self.client.doql(query)
        except Device42Error:
            return

        by_device: dict[int, list[str]] = {}
        seen_labels: dict[int, set[str]] = {}
        for row in rows:
            device_fk = _as_int(row.get("device_fk"))
            if device_fk is None:
                continue
            label = _source_label(row)
            labels = seen_labels.setdefault(device_fk, set())
            if label in labels:
                continue
            labels.add(label)
            by_device.setdefault(device_fk, []).append(label)

        for hit in hits.values():
            if hit.kind != "device" or hit.object_id is None:
                continue
            sources = by_device.get(hit.object_id) or []
            hit.sources = sources[:6]

    def _rest_fallback(self, term: str, limit: int, hits: dict[str, InventoryHit]) -> None:
        try:
            for device in self.client.search_devices_by_name(term, limit):
                hit = self._hit_from_rest_device(device)
                self._merge(hits, hit)
        except Device42Error:
            pass

        try:
            for asset in self.client.search_assets_by_name(term, limit):
                hit = self._hit_from_rest_asset(asset)
                self._merge(hits, hit)
        except Device42Error:
            pass

        if looks_like_ip(term) or any(ch.isdigit() for ch in term):
            try:
                for ip_row in self.client.search_ips(term, limit):
                    hit = self._hit_from_rest_ip(ip_row)
                    self._merge(hits, hit)
            except Device42Error:
                pass

    def _hit_from_rest_device(self, device: dict) -> InventoryHit:
        object_id = _as_int(device.get("device_id") or device.get("id"))
        name = str(device.get("name") or "")
        ips = _split_csv(device.get("ip_addresses") or device.get("ips"))
        aliases = _split_csv(device.get("aliases"))
        return InventoryHit(
            kind="device",
            object_id=object_id,
            name=name,
            fqdn=_pick_fqdn(name, aliases),
            ips=ips,
            aliases=aliases,
            object_type=str(device.get("type") or ""),
            os_name=str(device.get("os") or device.get("os_name") or ""),
            service_level=str(device.get("service_level") or ""),
            in_service=str(device.get("in_service") or ""),
            last_seen=_parse_dt(device.get("last_discovered") or device.get("last_changed")),
            last_seen_label=relative_age(
                _parse_dt(device.get("last_discovered") or device.get("last_changed"))
            ),
            matched_on=["name"],
            raw=device,
        )

    def _hit_from_rest_asset(self, asset: dict) -> InventoryHit:
        last_seen = _parse_dt(asset.get("last_changed") or asset.get("last_edited"))
        return InventoryHit(
            kind="asset",
            object_id=_as_int(asset.get("asset_id") or asset.get("id")),
            name=str(asset.get("name") or ""),
            object_type=str(asset.get("type") or ""),
            service_level=str(asset.get("service_level") or ""),
            last_seen=last_seen,
            last_seen_label=relative_age(last_seen),
            sources=["asset record"],
            matched_on=["name"],
            raw=asset,
        )

    def _hit_from_rest_ip(self, ip_row: dict) -> InventoryHit:
        device_name = str(ip_row.get("device") or ip_row.get("device_name") or "")
        ip = str(ip_row.get("ip") or ip_row.get("ip_address") or "")
        return InventoryHit(
            kind="device",
            object_id=_as_int(ip_row.get("device_id")),
            name=device_name or ip,
            ips=[ip] if ip else [],
            matched_on=["ip"],
            last_seen=_parse_dt(ip_row.get("last_discovered") or ip_row.get("last_changed")),
            last_seen_label=relative_age(
                _parse_dt(ip_row.get("last_discovered") or ip_row.get("last_changed"))
            ),
            raw=ip_row,
        )

    @staticmethod
    def _merge(hits: dict[str, InventoryHit], hit: InventoryHit) -> None:
        if hit.object_id is not None:
            key = f"{hit.kind}:{hit.object_id}"
        else:
            key = f"{hit.kind}:name:{hit.name.lower()}"
        existing = hits.get(key)
        if not existing:
            hits[key] = hit
            return
        for ip in hit.ips:
            if ip not in existing.ips:
                existing.ips.append(ip)
        for alias in hit.aliases:
            if alias not in existing.aliases:
                existing.aliases.append(alias)
        for label in hit.matched_on:
            if label not in existing.matched_on:
                existing.matched_on.append(label)
        for src in hit.sources:
            if src not in existing.sources:
                existing.sources.append(src)
        if not existing.fqdn and hit.fqdn:
            existing.fqdn = hit.fqdn
        if not existing.name and hit.name:
            existing.name = hit.name
        if not existing.object_type and hit.object_type:
            existing.object_type = hit.object_type
        if not existing.os_name and hit.os_name:
            existing.os_name = hit.os_name
        if existing.last_seen is None and hit.last_seen is not None:
            existing.last_seen = hit.last_seen
            existing.last_seen_label = hit.last_seen_label


def _as_int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None
