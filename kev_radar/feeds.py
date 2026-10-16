"""Load bundled snapshots and, when asked, refresh them from public feeds.

The dashboard always has the files under ``data/snapshots``. A live pull is
optional and cached by the Streamlit entrypoint for a day.
"""

from __future__ import annotations

import json
from datetime import date, datetime, timezone
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT_DIR = ROOT / "data" / "snapshots"
DEMO_CSV = ROOT / "data" / "demo" / "tenable_findings.csv"

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
CVE_URL = "https://cveawg.mitre.org/api/cve/{cve}"

CVSS_KEYS = ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0", "cvssV2")


def snapshot_path(name: str) -> Path:
    return SNAPSHOT_DIR / name


def load_json(name: str) -> dict | list:
    return json.loads(snapshot_path(name).read_text(encoding="utf-8"))


def write_json(name: str, payload: object) -> None:
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    snapshot_path(name).write_text(json.dumps(payload, indent=1), encoding="utf-8")


def kev_index(catalog: dict) -> dict[str, dict]:
    return {
        str(entry.get("cveID", "")).upper(): entry
        for entry in catalog.get("vulnerabilities", [])
        if entry.get("cveID")
    }


def epss_index(payload: dict) -> dict[str, dict]:
    scores = payload.get("scores") if isinstance(payload, dict) else None
    if not isinstance(scores, dict):
        return {}
    cleaned = {}
    for cve, value in scores.items():
        if isinstance(value, dict) and value.get("epss") is not None:
            cleaned[str(cve).upper()] = value
        elif value is not None:
            cleaned[str(cve).upper()] = {"epss": value}
    return cleaned


def load_bundle() -> dict:
    """Read the offline bundle. Raises FileNotFoundError if the snapshot is missing."""
    catalog = load_json("kev.json")
    previous_path = snapshot_path("kev_previous.json")
    previous = json.loads(previous_path.read_text(encoding="utf-8")) if previous_path.exists() else None
    epss_payload = load_json("epss.json") if snapshot_path("epss.json").exists() else {"scores": {}}
    ssvc = load_json("vulnrichment.json") if snapshot_path("vulnrichment.json").exists() else {}
    meta = load_json("metadata.json") if snapshot_path("metadata.json").exists() else {}
    pool = load_json("cve_pool.json") if snapshot_path("cve_pool.json").exists() else []
    msrc = load_json("msrc_kb.json") if snapshot_path("msrc_kb.json").exists() else {"cves": {}}
    return {
        "catalog": catalog,
        "previous": previous,
        "kev_by_id": kev_index(catalog),
        "epss": epss_index(epss_payload),
        "epss_date": epss_payload.get("score_date") if isinstance(epss_payload, dict) else None,
        "ssvc": {str(key).upper(): value for key, value in ssvc.items()},
        "metadata": meta,
        "pool": pool,
        "msrc": msrc if isinstance(msrc, dict) else {"cves": {}},
    }


def snapshot_age_hours(metadata: dict, now: datetime | None = None) -> float | None:
    raw = metadata.get("fetched_at") if metadata else None
    if not raw:
        return None
    try:
        fetched = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None
    if fetched.tzinfo is None:
        fetched = fetched.replace(tzinfo=timezone.utc)
    current = now or datetime.now(timezone.utc)
    return (current - fetched).total_seconds() / 3600


def fetch_json(url: str, *, params: dict | None = None, timeout: float = 40) -> dict:
    response = requests.get(
        url,
        params=params,
        timeout=timeout,
        headers={"User-Agent": "kev-radar-portfolio/1.0 (public-data demo)"},
    )
    response.raise_for_status()
    return response.json()


def fetch_kev() -> dict:
    return fetch_json(KEV_URL, timeout=60)


def fetch_epss(cves: list[str]) -> list[dict]:
    """Ask FIRST for EPSS. The public API returns at most 100 CVEs per call."""
    if not cves:
        return []
    joined = ",".join(cves)
    payload = fetch_json(EPSS_URL, params={"cve": joined})
    return list(payload.get("data") or [])


def fetch_cve_record(cve: str) -> dict:
    return fetch_json(CVE_URL.format(cve=cve), timeout=30)


def _cvss_from_metrics(metrics: list | None) -> tuple[float | None, str | None, str | None]:
    for metric in metrics or []:
        if not isinstance(metric, dict):
            continue
        for key in CVSS_KEYS:
            block = metric.get(key)
            if isinstance(block, dict) and block.get("baseScore") is not None:
                return float(block["baseScore"]), block.get("vectorString"), str(block.get("version") or key)
    return None, None, None


def extract_enrichment(record: dict) -> dict:
    """Pull SSVC decision points and a CVSS base score out of a CVE record.

    CVSS on the CNA container wins over the CISA ADP container, matching CISA's
    Vulnrichment guidance. SSVC options are read from ADP containers.
    """
    containers = record.get("containers") or {}
    cna = containers.get("cna") or {}
    adp = containers.get("adp") or []
    cvss, vector, version = _cvss_from_metrics(cna.get("metrics"))
    automatable = technical = exploitation = ssvc_version = None
    for container in adp:
        if not isinstance(container, dict):
            continue
        if cvss is None:
            cvss, vector, version = _cvss_from_metrics(container.get("metrics"))
        for metric in container.get("metrics") or []:
            other = metric.get("other") if isinstance(metric, dict) else None
            if not isinstance(other, dict) or other.get("type") != "ssvc":
                continue
            content = other.get("content") or {}
            ssvc_version = content.get("version") or ssvc_version
            for option in content.get("options") or []:
                if not isinstance(option, dict):
                    continue
                if "Automatable" in option:
                    automatable = option["Automatable"]
                if "Technical Impact" in option:
                    technical = option["Technical Impact"]
                if "Exploitation" in option:
                    exploitation = option["Exploitation"]
    return {
        "automatable": None if automatable is None else str(automatable).lower(),
        "technical_impact": None if technical is None else str(technical).lower(),
        "exploitation": None if exploitation is None else str(exploitation).lower(),
        "cvss": cvss,
        "cvss_vector": vector,
        "cvss_version": version,
        "ssvc_version": ssvc_version,
    }


def parse_iso_date(value: object) -> date | None:
    if value is None or str(value).strip() == "":
        return None
    text = str(value).strip()[:10]
    try:
        year, month, day = (int(part) for part in text.split("-"))
        return date(year, month, day)
    except ValueError:
        return None
