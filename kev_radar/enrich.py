"""Live CISA Vulnrichment lookups for CVEs missing from the snapshot.

The snapshot in ``data/snapshots/vulnrichment.json`` covers the demo pool.
An uploaded CVE that is not in that file is fetched from the public
cisagov/vulnrichment GitHub repository, one CVE record at a time. A 404
means CISA has not published enrichment; the caller keeps the BOD 26-04
missing-data fallback and marks the row assumed. Any other failure is
raised so the caller can fall back without caching the error.
"""

from __future__ import annotations

import re

from kev_radar.feeds import extract_enrichment

VULNRICHMENT_RAW = (
    "https://raw.githubusercontent.com/cisagov/vulnrichment/"
    "develop/{year}/{bucket}/{cve}.json"
)
_CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,})$", re.IGNORECASE)


class EnrichmentLookupError(RuntimeError):
    """The Vulnrichment repository could not be read for this CVE."""


def vulnrichment_url(cve: str) -> str:
    """Path used by cisagov/vulnrichment: ``YEAR/{thousands}xxx/CVE-....json``."""
    match = _CVE_RE.match(str(cve).strip().upper())
    if match is None:
        raise ValueError(f"{cve} is not a CVE id")
    year, number = match.group(1), int(match.group(2))
    bucket = f"{number // 1000}xxx"
    return VULNRICHMENT_RAW.format(year=year, bucket=bucket, cve=match.group(0).upper())


def fetch_enrichment(cve: str, *, getter=None) -> dict:
    """Return SSVC fields for one CVE.

    ``found`` is False when the repository has no file (HTTP 404). Other
    errors raise ``EnrichmentLookupError``.
    """
    url = vulnrichment_url(cve)
    fetch = getter or _default_get
    try:
        status, payload = fetch(url)
    except EnrichmentLookupError:
        raise
    except Exception as exc:
        raise EnrichmentLookupError(f"Vulnrichment lookup failed for {cve}") from exc
    if status == 404 or payload is None:
        return {"found": False, "source": "cisagov/vulnrichment", "cve": cve.upper()}
    if status and int(status) >= 400:
        raise EnrichmentLookupError(f"Vulnrichment returned HTTP {status} for {cve}")
    fields = extract_enrichment(payload if isinstance(payload, dict) else {})
    fields["found"] = True
    fields["source"] = "cisagov/vulnrichment"
    fields["cve"] = str(cve).upper()
    return fields


def _default_get(url: str) -> tuple[int, dict | None]:
    import requests

    try:
        response = requests.get(
            url,
            timeout=30,
            headers={"User-Agent": "kev-radar/1.0 (+https://github.com/Dexious123/kev-radar)"},
        )
    except requests.RequestException as exc:
        raise EnrichmentLookupError(str(exc)) from exc
    if response.status_code == 404:
        return 404, None
    if response.status_code >= 400:
        raise EnrichmentLookupError(f"HTTP {response.status_code} for {url}")
    return response.status_code, response.json()


def supplement_ssvc(
    snapshot: dict[str, dict],
    cves: list[str],
    *,
    fetch,
    limit: int = 40,
    resolved: dict[str, dict] | None = None,
) -> tuple[dict[str, dict], dict]:
    """Fill SSVC gaps from ``fetch(cve) -> enrichment dict``.

    ``fetch`` should return a dict with ``found``. It may raise; a raise is
    recorded as a failure and the snapshot value (or the absence of one)
    stays in place. At most ``limit`` new lookups are made per call.

    ``resolved`` carries lookups from earlier calls (CVE -> record, or
    ``{"found": False}`` for a 404) and is updated in place. Those CVEs are not
    looked up again and do not count toward ``limit``, so a long upload is
    enriched batch by batch instead of retrying the same first batch forever.
    Failures are not stored, so they are retried.
    """
    merged = {str(key).upper(): value for key, value in (snapshot or {}).items()}
    report: dict[str, list[str]] = {
        "fetched": [],
        "not_published": [],
        "failed": [],
        "skipped": [],
    }
    missing: list[str] = []
    seen: set[str] = set()
    for raw in cves:
        cve = str(raw).upper()
        if not cve or cve in seen:
            continue
        seen.add(cve)
        if cve in merged:
            continue
        earlier = (resolved or {}).get(cve)
        if earlier is None:
            missing.append(cve)
        elif earlier.get("found"):
            merged[cve] = earlier
            report["fetched"].append(cve)
        else:
            report["not_published"].append(cve)
    calls = 0
    for cve in missing:
        if calls >= limit:
            report["skipped"].append(cve)
            continue
        calls += 1
        try:
            record = fetch(cve)
        except Exception:
            report["failed"].append(cve)
            continue
        if not isinstance(record, dict) or not record.get("found"):
            report["not_published"].append(cve)
            if resolved is not None:
                resolved[cve] = {"found": False}
            continue
        merged[cve] = record
        report["fetched"].append(cve)
        if resolved is not None:
            resolved[cve] = record
    return merged, report


def ssvc_from_enrichment(record: dict | None) -> dict | None:
    """Drop lookup bookkeeping so the row matches the snapshot shape."""
    if not record or not record.get("found"):
        return None
    return {
        "automatable": record.get("automatable"),
        "technical_impact": record.get("technical_impact"),
        "exploitation": record.get("exploitation"),
        "cvss": record.get("cvss"),
        "cvss_vector": record.get("cvss_vector"),
        "cvss_version": record.get("cvss_version"),
        "ssvc_version": record.get("ssvc_version"),
        "source": record.get("source") or "cisagov/vulnrichment",
    }


