"""Parse a Tenable Vulnerability Management findings export.

The column names follow Tenable's findings CSV keys
(https://docs.tenable.com/vulnerability-management/Content/Explore/export-findings-csv-keys.htm).
Older Nessus / Tenable.sc headers are accepted as aliases. Rows are exploded
to one CVE per row, then collapsed to a unique host + CVE.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import NamedTuple

import pandas as pd

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

COLUMN_ALIASES: dict[str, tuple[str, ...]] = {
    "plugin_id": ("definition.id", "plugin id", "plugin_id", "plugin"),
    "plugin_name": ("definition.name", "plugin name", "name", "finding name"),
    "cve": ("definition.cve", "cve", "cves", "definition.cves"),
    "cvss": (
        "definition.cvss3.base_score",
        "cvssv3 base score",
        "cvss v3 base score",
        "cvss v3.0 base score",
        "cvss v3.1 base score",
        "cvss3 base score",
        "cvss",
        "cvss v2.0 base score",
        "definition.cvss2.base_score",
    ),
    "cvss_vector": (
        "definition.cvss3.base_vector",
        "cvss v3 vector",
        "cvssv3 vector",
        "cvss vector",
    ),
    "severity": ("severity", "risk", "risk factor", "definition.severity"),
    "host_name": (
        "asset.host_name",
        "host",
        "dns name",
        "fqdn",
        "asset.display_fqdn",
        "netbios name",
        "asset.netbios_name",
    ),
    "asset_name": ("asset.name", "asset name"),
    "ip": (
        "asset.display_ipv4_address",
        "ip address",
        "ipv4 address",
        "host ip",
        "asset.ipv4_addresses",
    ),
    "operating_system": ("asset.operating_system", "operating system", "os"),
    "system_type": ("asset.system_type", "system type", "asset type"),
    "tags": ("asset.tags", "tags"),
    "owner": ("owner", "asset owner", "system owner"),
    "business_unit": ("business unit", "bu", "department"),
    "internet_exposed": (
        "internet exposed",
        "publicly exposed",
        "internet facing",
        "exposure",
    ),
    "generally_public_facing": (
        "generally public-facing",
        "generally public facing",
        "public facing software",
        "public-facing software",
    ),
    "port": ("port",),
    "protocol": ("protocol",),
    "output": ("output", "plugin output"),
    "solution": ("definition.solution", "solution"),
    "synopsis": ("definition.synopsis", "synopsis"),
    "state": ("state", "finding state", "status"),
    "first_observed": ("first_observed", "first seen", "first found", "first discovered"),
    "last_seen": ("last_seen", "last seen", "last found", "last observed"),
    "last_fixed": ("last_fixed", "last fixed", "fixed date"),
    "scanner_epss": ("definition.epss.score", "epss", "epss score"),
}

OWNER_KEYS = {"owner", "asset owner", "system owner", "owned by"}
BU_KEYS = {"business unit", "bu", "department", "org", "organization"}
EXPOSURE_KEYS = {
    "internet exposed",
    "publicly exposed",
    "exposure",
    "internet facing",
    "internet-facing",
    "public exposure",
}
TYPE_KEYS = {"asset type", "system type", "system_type", "type"}
PUBLIC_FACING_KEYS = {
    "generally public-facing",
    "generally public facing",
    "public facing software",
    "public-facing software",
}

YES_VALUES = {"yes", "y", "true", "1", "internet", "public", "external", "exposed"}
NO_VALUES = {"no", "n", "false", "0", "internal", "private"}

SEVERITY_RANK = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}

FINDING_COLUMNS = [
    "host_key",
    "host_name",
    "asset_name",
    "ip",
    "operating_system",
    "system_type",
    "owner",
    "business_unit",
    "exposed",
    "exposure_reason",
    "exposure_basis",
    "public_facing_tag",
    "cve",
    "plugin_ids",
    "plugin_name",
    "severity",
    "cvss",
    "cvss_vector",
    "port",
    "protocol",
    "output",
    "solution",
    "state",
    "first_observed",
    "last_seen",
    "last_fixed",
    "raw_row_count",
    "scanner_epss",
]


class ParseError(ValueError):
    """The file is not a usable Tenable-style findings export."""


@dataclass
class ParseResult:
    findings: pd.DataFrame
    raw_rows: int
    collapsed_findings: int
    skipped_no_cve: int
    skipped_no_host: int
    duplicate_rows: int
    warnings: list[str] = field(default_factory=list)


def _blank(value: object) -> bool:
    if value is None:
        return True
    text = str(value).strip()
    return text == "" or text.lower() in {"nan", "none", "null", "nat"}


def _text(value: object) -> str | None:
    if _blank(value):
        return None
    return str(value).strip()


def _header_map(columns: list[str]) -> dict[str, str]:
    return {column.strip().lower(): column for column in columns}


def _pick(columns: dict[str, str], aliases: tuple[str, ...]) -> str | None:
    for alias in aliases:
        if alias in columns:
            return columns[alias]
    return None


def _parse_date(value: object) -> object:
    text = _text(value)
    if text is None:
        return None
    parsed = pd.to_datetime(text, utc=True, errors="coerce")
    if pd.isna(parsed):
        parsed = pd.to_datetime(text, errors="coerce")
    if pd.isna(parsed):
        return None
    return parsed.date()


def _parse_float(value: object) -> float | None:
    text = _text(value)
    if text is None:
        return None
    # Tenable sometimes exports several CVEs' scores in one cell.
    match = re.search(r"\d+(?:\.\d+)?", text)
    if not match:
        return None
    try:
        return float(match.group(0))
    except ValueError:
        return None


def _severity(value: object, cvss: float | None) -> str:
    text = _text(value)
    if text is not None:
        key = text.lower()
        named = {
            "critical": "Critical",
            "4": "Critical",
            "high": "High",
            "3": "High",
            "medium": "Medium",
            "moderate": "Medium",
            "2": "Medium",
            "low": "Low",
            "1": "Low",
            "info": "Info",
            "informational": "Info",
            "none": "Info",
            "0": "Info",
        }
        if key in named:
            return named[key]
    if cvss is None:
        return "Medium"
    if cvss >= 9:
        return "Critical"
    if cvss >= 7:
        return "High"
    if cvss >= 4:
        return "Medium"
    if cvss > 0:
        return "Low"
    return "Info"


def _state(value: object, last_fixed: object) -> str:
    text = _text(value)
    if text is None:
        return "fixed" if last_fixed is not None else "open"
    key = text.lower().replace("_", " ")
    if key in {"fixed", "closed", "resolved"}:
        return "fixed"
    if key in {"reopened", "re opened"}:
        return "reopened"
    return "open"


def _flatten_tags(value: object) -> dict[str, str]:
    text = _text(value)
    if text is None:
        return {}
    parsed: object | None = None
    if text[0] in "{[":
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
    result: dict[str, str] = {}
    if isinstance(parsed, dict):
        for key, raw in parsed.items():
            if isinstance(raw, list):
                joined = ", ".join(str(item) for item in raw if not _blank(item))
            elif isinstance(raw, dict):
                joined = json.dumps(raw)
            else:
                joined = "" if raw is None else str(raw)
            if joined.strip():
                result[str(key).strip().lower()] = joined.strip()
        return result
    for part in re.split(r"[|;]", text):
        if ":" not in part:
            continue
        key, raw = part.split(":", 1)
        if key.strip() and raw.strip():
            result[key.strip().lower()] = raw.strip()
    return result


def _lookup_tag(tags: dict[str, str], keys: set[str]) -> str | None:
    for key in keys:
        if key in tags and tags[key]:
            return tags[key]
    return None


def _yes_no(value: str | None) -> bool | None:
    if value is None:
        return None
    token = value.strip().lower()
    if token in YES_VALUES:
        return True
    if token in NO_VALUES:
        return False
    return None


def _looks_like_ip(value: str | None) -> bool:
    if not value:
        return False
    candidate = value.strip().split()[0].split(",")[0]
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True


def is_public_routable(value: str | None) -> bool:
    """True when the address is a globally routable unicast IP."""
    if not value:
        return False
    # A cell can list several addresses. Any public one is enough.
    candidates = re.split(r"[\s,;]+", value.strip())
    for candidate in candidates:
        if not candidate:
            continue
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if getattr(ip, "is_global", False):
            return True
    return False


class ExposureCall(NamedTuple):
    exposed: bool
    reason: str
    basis: str


def infer_exposure(
    tag_value: bool | None,
    ip: str | None,
    asset_type: str | None,
) -> ExposureCall:
    """Apply the asset tag, then the first two CISA best-effort steps.

    An explicit tag wins. Otherwise a publicly routable address is public,
    then an asset-type tag of "network". The generally-public-facing step
    needs the CVE's KEV status, so a row that reaches none of these stays
    ``unresolved`` until prioritize runs.
    """
    if tag_value is True:
        return ExposureCall(True, "Exposure tag says the asset is publicly exposed.", "tag")
    if tag_value is False:
        return ExposureCall(False, "Exposure tag says the asset is not publicly exposed.", "tag")
    if is_public_routable(ip):
        return ExposureCall(
            True,
            "No exposure tag. The address is publicly routable, so CISA's fallback treats it as public.",
            "public_address",
        )
    if asset_type and asset_type.strip().lower() == "network":
        return ExposureCall(
            True,
            "No exposure tag. Asset type is network, so CISA's fallback treats it as public.",
            "asset_type",
        )
    return ExposureCall(
        False,
        "No exposure tag, no public address, and asset type is not network. Treated as internal.",
        "unresolved",
    )


def _cves_in(value: object) -> list[str]:
    text = _text(value)
    if text is None:
        return []
    found = CVE_RE.findall(text)
    seen: list[str] = []
    for cve in found:
        normalized = cve.upper()
        if normalized not in seen:
            seen.append(normalized)
    return seen


def _read_frame(source: object) -> pd.DataFrame:
    try:
        frame = pd.read_csv(source, dtype=str, keep_default_na=False)
    except pd.errors.EmptyDataError as exc:
        raise ParseError("The CSV is empty.") from exc
    except UnicodeDecodeError:
        if hasattr(source, "seek"):
            source.seek(0)
        frame = pd.read_csv(source, dtype=str, keep_default_na=False, encoding="latin-1")
    if frame.shape[1] == 1 and frame.columns[0] and ";" in str(frame.columns[0]):
        if hasattr(source, "seek"):
            source.seek(0)
        frame = pd.read_csv(source, dtype=str, keep_default_na=False, sep=";")
    return frame


def _empty_findings() -> pd.DataFrame:
    return pd.DataFrame(columns=FINDING_COLUMNS)


def parse_findings(source: object) -> ParseResult:
    """Parse an upload, path, or file-like object into host + CVE findings."""
    frame = _read_frame(source)
    if frame.empty and len(frame.columns) == 0:
        raise ParseError("The CSV is empty.")
    columns = _header_map(list(frame.columns))
    cve_col = _pick(columns, COLUMN_ALIASES["cve"])
    host_col = _pick(columns, COLUMN_ALIASES["host_name"])
    asset_col = _pick(columns, COLUMN_ALIASES["asset_name"])
    ip_col = _pick(columns, COLUMN_ALIASES["ip"])
    if cve_col is None or (host_col is None and asset_col is None and ip_col is None):
        raise ParseError(
            "This CSV doesn't look like a Tenable findings export. "
            "It needs a CVE column (definition.cve or CVE) and a host column "
            "(asset.host_name, asset.name, Host, or an IP address)."
        )

    def column(name: str) -> str | None:
        return _pick(columns, COLUMN_ALIASES[name])

    picked = {name: column(name) for name in COLUMN_ALIASES}
    warnings: list[str] = []
    exploded: list[dict] = []
    skipped_no_cve = 0
    skipped_no_host = 0

    for record in frame.to_dict(orient="records"):
        cves = _cves_in(record.get(cve_col)) if cve_col else []
        host_name = _text(record.get(picked["host_name"])) if picked["host_name"] else None
        asset_name = _text(record.get(picked["asset_name"])) if picked["asset_name"] else None
        ip = _text(record.get(picked["ip"])) if picked["ip"] else None
        if ip is None and is_public_routable(host_name):
            ip = host_name
        elif ip is None and host_name and _looks_like_ip(host_name):
            ip = host_name
        host_key = host_name or asset_name or ip
        if host_key is None:
            skipped_no_host += 1
            continue
        if not cves:
            skipped_no_cve += 1
            continue
        tags = _flatten_tags(record.get(picked["tags"])) if picked["tags"] else {}
        owner = _text(record.get(picked["owner"])) if picked["owner"] else None
        business_unit = _text(record.get(picked["business_unit"])) if picked["business_unit"] else None
        exposed_cell = _text(record.get(picked["internet_exposed"])) if picked["internet_exposed"] else None
        if owner is None:
            owner = _lookup_tag(tags, OWNER_KEYS)
        if business_unit is None:
            business_unit = _lookup_tag(tags, BU_KEYS)
        exposure_token = exposed_cell if exposed_cell is not None else _lookup_tag(tags, EXPOSURE_KEYS)
        facing_cell = (
            _text(record.get(picked["generally_public_facing"]))
            if picked["generally_public_facing"]
            else None
        )
        if facing_cell is None:
            facing_cell = _lookup_tag(tags, PUBLIC_FACING_KEYS)
        system_type = _text(record.get(picked["system_type"])) if picked["system_type"] else None
        if system_type is None:
            system_type = _lookup_tag(tags, TYPE_KEYS)
        cvss = _parse_float(record.get(picked["cvss"])) if picked["cvss"] else None
        last_fixed = _parse_date(record.get(picked["last_fixed"])) if picked["last_fixed"] else None
        row_base = {
            "host_key": host_key.strip().lower(),
            "host_name": host_name or asset_name or host_key,
            "asset_name": asset_name or host_name or host_key,
            "ip": ip,
            "operating_system": _text(record.get(picked["operating_system"])) if picked["operating_system"] else None,
            "system_type": system_type,
            "owner": owner or "Unassigned",
            "business_unit": business_unit or "Unassigned",
            "exposed_tag": _yes_no(exposure_token),
            "public_facing_tag": _yes_no(facing_cell),
            "cve": "",
            "plugin_id": _text(record.get(picked["plugin_id"])) if picked["plugin_id"] else None,
            "plugin_name": _text(record.get(picked["plugin_name"])) if picked["plugin_name"] else None,
            "severity": _severity(record.get(picked["severity"]) if picked["severity"] else None, cvss),
            "cvss": cvss,
            "cvss_vector": _text(record.get(picked["cvss_vector"])) if picked["cvss_vector"] else None,
            "port": _text(record.get(picked["port"])) if picked["port"] else None,
            "protocol": _text(record.get(picked["protocol"])) if picked["protocol"] else None,
            "output": _text(record.get(picked["output"])) if picked["output"] else None,
            "solution": _text(record.get(picked["solution"])) if picked["solution"] else None,
            "state": _state(record.get(picked["state"]) if picked["state"] else None, last_fixed),
            "first_observed": _parse_date(record.get(picked["first_observed"])) if picked["first_observed"] else None,
            "last_seen": _parse_date(record.get(picked["last_seen"])) if picked["last_seen"] else None,
            "last_fixed": last_fixed,
            "scanner_epss": _parse_float(record.get(picked["scanner_epss"])) if picked["scanner_epss"] else None,
        }
        for cve in cves:
            exploded.append({**row_base, "cve": cve})

    if skipped_no_cve:
        warnings.append(
            f"{skipped_no_cve} row(s) had no CVE and were left out of the priority queue."
        )
    if skipped_no_host:
        warnings.append(f"{skipped_no_host} row(s) had no host and were skipped.")

    findings = _collapse(exploded)
    duplicate_rows = max(0, len(exploded) - len(findings))
    if findings.empty:
        warnings.append("No host + CVE findings were left after parsing.")
    return ParseResult(
        findings=findings,
        raw_rows=int(len(frame)),
        collapsed_findings=int(len(findings)),
        skipped_no_cve=skipped_no_cve,
        skipped_no_host=skipped_no_host,
        duplicate_rows=duplicate_rows,
        warnings=warnings,
    )


def _min_date(values: list[object]) -> object:
    present = [value for value in values if value is not None]
    return min(present) if present else None


def _max_date(values: list[object]) -> object:
    present = [value for value in values if value is not None]
    return max(present) if present else None


def _join_unique(values: list[object]) -> str | None:
    seen: list[str] = []
    for value in values:
        text = _text(value)
        if text and text not in seen:
            seen.append(text)
    return ", ".join(seen) if seen else None


def _collapse(rows: list[dict]) -> pd.DataFrame:
    if not rows:
        return _empty_findings()
    groups: dict[tuple[str, str], list[dict]] = {}
    for row in rows:
        groups.setdefault((row["host_key"], row["cve"]), []).append(row)
    collapsed: list[dict] = []
    for (host_key, cve), members in groups.items():
        states = {member["state"] for member in members}
        if "open" in states:
            state = "open"
        elif "reopened" in states:
            state = "reopened"
        else:
            state = "fixed"
        ranked = sorted(members, key=lambda member: SEVERITY_RANK.get(member["severity"], 0), reverse=True)
        primary = ranked[0]
        cvss_values = [member["cvss"] for member in members if member["cvss"] is not None]
        epss_values = [member["scanner_epss"] for member in members if member["scanner_epss"] is not None]
        tag_values = [member["exposed_tag"] for member in members if member["exposed_tag"] is not None]
        exposed_tag = True if any(tag_values) else (False if tag_values else None)
        facing_values = [
            member["public_facing_tag"] for member in members if member["public_facing_tag"] is not None
        ]
        public_facing_tag = True if any(facing_values) else (False if facing_values else None)
        exposed, reason, basis = infer_exposure(exposed_tag, primary["ip"], primary["system_type"])
        last_fixed = _max_date([member["last_fixed"] for member in members]) if state == "fixed" else None
        collapsed.append(
            {
                "host_key": host_key,
                "host_name": primary["host_name"],
                "asset_name": primary["asset_name"],
                "ip": primary["ip"],
                "operating_system": primary["operating_system"],
                "system_type": primary["system_type"],
                "owner": primary["owner"],
                "business_unit": primary["business_unit"],
                "exposed": exposed,
                "exposure_reason": reason,
                "exposure_basis": basis,
                "public_facing_tag": public_facing_tag,
                "cve": cve,
                "plugin_ids": _join_unique([member["plugin_id"] for member in members]),
                "plugin_name": primary["plugin_name"] or cve,
                "severity": primary["severity"],
                "cvss": max(cvss_values) if cvss_values else None,
                "cvss_vector": primary["cvss_vector"],
                "port": _join_unique([member["port"] for member in members]),
                "protocol": _join_unique([member["protocol"] for member in members]),
                "output": primary["output"],
                "solution": primary["solution"],
                "state": state,
                "first_observed": _min_date([member["first_observed"] for member in members]),
                "last_seen": _max_date([member["last_seen"] for member in members]),
                "last_fixed": last_fixed,
                "raw_row_count": len(members),
                "scanner_epss": max(epss_values) if epss_values else None,
            }
        )
    findings = pd.DataFrame(collapsed, columns=FINDING_COLUMNS)
    return findings.sort_values(["host_name", "cve"]).reset_index(drop=True)
