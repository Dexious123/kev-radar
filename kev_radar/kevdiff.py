"""KEV-this-week diff against the estate.

``forensicTriage`` arrived with BOD 26-04. Feeds and older snapshots that
omit the key are reported as "not in this feed" instead of failing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, timedelta

TRIAGE_YES = "yes"
TRIAGE_NO = "no"
TRIAGE_MISSING = "not_in_feed"
TRIAGE_UNKNOWN = "unrecognized"


def triage_status(entry: dict) -> str:
    """Read forensicTriage without assuming the key exists."""
    if "forensicTriage" not in entry:
        return TRIAGE_MISSING
    raw = entry.get("forensicTriage")
    if raw is None or str(raw).strip() == "":
        return TRIAGE_MISSING
    value = str(raw).strip().lower()
    if value in {"yes", "y", "true"}:
        return TRIAGE_YES
    if value in {"no", "n", "false"}:
        return TRIAGE_NO
    return TRIAGE_UNKNOWN


def ransomware_known(entry: dict) -> bool:
    return str(entry.get("knownRansomwareCampaignUse", "")).strip().lower() == "known"


def _parse_date(value: object) -> date | None:
    if value is None or str(value).strip() == "":
        return None
    text = str(value).strip()[:10]
    try:
        year, month, day = (int(part) for part in text.split("-"))
        return date(year, month, day)
    except ValueError:
        return None


def added_between(vulnerabilities: list[dict], start: date, end: date) -> list[dict]:
    """Entries whose dateAdded falls on start through end, inclusive."""
    selected = []
    for entry in vulnerabilities:
        added = _parse_date(entry.get("dateAdded"))
        if added is not None and start <= added <= end:
            selected.append(entry)
    return selected


def new_since_previous(current: list[dict], previous: list[dict] | None) -> list[dict]:
    """Catalog entries whose CVE ID is absent from the previous snapshot."""
    if not previous:
        return []
    seen = {str(entry.get("cveID", "")).upper() for entry in previous}
    return [entry for entry in current if str(entry.get("cveID", "")).upper() not in seen]


@dataclass
class EstateHit:
    host_name: str
    owner: str
    business_unit: str
    exposed: bool
    state: str


@dataclass
class WeekItem:
    cve: str
    vendor: str
    product: str
    name: str
    date_added: date | None
    due_date: date | None
    ransomware: bool
    triage: str
    required_action: str
    in_estate: bool
    hits: list[EstateHit] = field(default_factory=list)
    source: str = "date_added"

    @property
    def host_count(self) -> int:
        return len(self.hits)

    @property
    def exposed_host_count(self) -> int:
        return sum(1 for hit in self.hits if hit.exposed)


def _item_from_entry(
    entry: dict,
    estate: dict[str, list[EstateHit]],
    source: str,
) -> WeekItem:
    cve = str(entry.get("cveID", "")).upper()
    hits = estate.get(cve, [])
    return WeekItem(
        cve=cve,
        vendor=str(entry.get("vendorProject") or ""),
        product=str(entry.get("product") or ""),
        name=str(entry.get("vulnerabilityName") or cve),
        date_added=_parse_date(entry.get("dateAdded")),
        due_date=_parse_date(entry.get("dueDate")),
        ransomware=ransomware_known(entry),
        triage=triage_status(entry),
        required_action=str(entry.get("requiredAction") or ""),
        in_estate=bool(hits),
        hits=list(hits),
        source=source,
    )


def kev_this_week(
    current: list[dict],
    previous: list[dict] | None,
    estate: dict[str, list[EstateHit]],
    as_of: date,
    *,
    window_days: int = 7,
) -> dict[str, list[WeekItem]]:
    """Return this week's additions and anything new since the previous snapshot.

    The week window is inclusive: ``window_days`` of 7 covers ``as_of`` and
    the six days before it.
    """
    start = as_of - timedelta(days=max(window_days, 1) - 1)
    by_date = [
        _item_from_entry(entry, estate, "date_added")
        for entry in added_between(current, start, as_of)
    ]
    by_date.sort(key=lambda item: (item.date_added or date.min, item.cve), reverse=True)
    dated_ids = {item.cve for item in by_date}
    diff_only = []
    for entry in new_since_previous(current, previous):
        cve = str(entry.get("cveID", "")).upper()
        if cve in dated_ids:
            continue
        diff_only.append(_item_from_entry(entry, estate, "snapshot_diff"))
    diff_only.sort(key=lambda item: item.cve)
    return {"this_week": by_date, "snapshot_only": diff_only}


def triage_label(status: str) -> str:
    return {
        TRIAGE_YES: "Yes",
        TRIAGE_NO: "No",
        TRIAGE_MISSING: "Not in this feed",
        TRIAGE_UNKNOWN: "Unrecognized value",
    }.get(status, "Not in this feed")


def render_monday_report(
    *,
    catalog_version: str,
    as_of: date,
    items: list[WeekItem],
    estate_name: str = "Harborline Mutual lab",
) -> str:
    """Weekly markdown briefing. Safe to archive; it only describes the synthetic estate."""
    hits = [item for item in items if item.in_estate]
    misses = [item for item in items if not item.in_estate]
    ransomware_hits = [item for item in hits if item.ransomware]
    triage_hits = [item for item in hits if item.triage == TRIAGE_YES]
    lines = [
        f"# KEV Monday — {as_of.isoformat()}",
        "",
        f"Estate: {estate_name} (synthetic). Catalog version {catalog_version or 'unknown'}.",
        "",
        (
            f"{len(items)} KEV entries were added in this window. "
            f"{len(hits)} hit this estate ({len(ransomware_hits)} with known ransomware use, "
            f"{len(triage_hits)} with forensicTriage = Yes)."
        ),
        "",
        "## In this estate",
        "",
    ]
    if not hits:
        lines.append("No new KEV entry this window matches a finding in the estate.")
        lines.append("")
    for item in hits:
        hosts = ", ".join(hit.host_name for hit in item.hits[:8])
        extra = ""
        if item.host_count > 8:
            extra = f" (+{item.host_count - 8} more)"
        lines.extend(
            [
                f"### {item.cve} — {item.name}",
                "",
                f"- Vendor / product: {item.vendor} / {item.product}",
                f"- Added: {item.date_added.isoformat() if item.date_added else 'unknown'}",
                f"- KEV due date: {item.due_date.isoformat() if item.due_date else 'unknown'}",
                f"- Known ransomware use: {'Known' if item.ransomware else 'Not known'}",
                f"- forensicTriage: {triage_label(item.triage)}",
                f"- Hosts ({item.host_count}, {item.exposed_host_count} exposed): {hosts}{extra}",
                "",
            ]
        )
    lines.extend(["## Not in this estate", ""])
    if not misses:
        lines.append("Every new KEV entry in this window matches at least one finding.")
        lines.append("")
    else:
        for item in misses:
            added = item.date_added.isoformat() if item.date_added else "unknown"
            lines.append(
                f"- {item.cve} ({item.vendor} {item.product}), added {added}, "
                f"ransomware {'Known' if item.ransomware else 'not known'}, "
                f"forensicTriage: {triage_label(item.triage)}"
            )
        lines.append("")
    lines.append(
        "Asset deadlines still come from the BOD 26-04 path (KEV, exposure, "
        "Automatable, Technical Impact). The catalog due date is CISA's "
        "catalog-level date, not a substitute for the asset decision."
    )
    lines.append("")
    return "\n".join(lines)
