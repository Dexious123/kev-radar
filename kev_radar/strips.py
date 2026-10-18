"""The top of the queue as flight strips: one row per CVE, in the order to work it.

Air traffic controllers sequence arrivals on printed strips with a colored edge. Here
the edge is the deadline band (past due, due within 7 days, later), the fixed-width
column carries the identifiers a patching lead copies into a ticket, and the last
column says why the CVE is on the list as short tags. One patch usually fixes every
host with the same CVE, so a strip lists them together; the CVE links to the fix queue.
"""

from __future__ import annotations

import html
import math
import re
from datetime import date

import pandas as pd

from kev_radar.present import queue_link, short_host
from kev_radar.radar import band_for


def _deadline(value) -> date | None:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return None
    if isinstance(value, pd.Timestamp):
        return value.date()
    return value if isinstance(value, date) else None


# The strip already shows how late a finding is, so the reason drops its timing phrase.
_TIMING = re.compile(r"^(\d+ days? overdue|due in \d+ days?|due today)$", re.IGNORECASE)
_TAG_NAMES = {
    "forensic triage required": "Forensic triage",
    "known ransomware use": "Ransomware",
    "publicly exposed": "Exposed",
}
_RULES = ("3 days + forensic triage", "3 days", "14 days", "60 days", "fix on system upgrade")


def tags(reason) -> list[tuple[str, str]]:
    """(kind, label) pairs from a fix reason. The deadline rule comes first and says 'forensic triage' once."""
    parts = [part.strip() for part in str(reason or "").split("·")]
    parts = [part for part in parts if part and not _TIMING.match(part)]
    rule = next((part for part in parts if part.lower() in _RULES), None)
    out: list[tuple[str, str]] = []
    if rule:
        out.append(("rule", rule))
    for part in parts:
        if part == rule:
            continue
        if part.lower() == "forensic triage required" and rule and "forensic triage" in rule.lower():
            continue
        label = _TAG_NAMES.get(part.lower(), part[:1].upper() + part[1:])
        out.append(("tag", label))
    return out


def _esc(value) -> str:
    return html.escape(str(value if value is not None else ""))


def _when(days: int | None) -> str:
    if days is None:
        return "No fixed deadline"
    if days < 0:
        late = -days
        return f"{late:,} day{'' if late == 1 else 's'} past due"
    if days == 0:
        return "Due today"
    return f"Due in {days:,} day{'' if days == 1 else 's'}"


def _first_and_more(values: list, noun: str = "") -> str:
    """'a' for one value, 'a and 3 more hosts' for several, so a strip stays one line per field."""
    rest = len(values) - 1
    if rest <= 0:
        return str(values[0]) if values else ""
    tail = f" {noun}{'' if rest == 1 or not noun else 's'}" if noun else ""
    return f"{values[0]} and {rest} more{tail}"


def render_strips(top: pd.DataFrame, as_of: date) -> str:
    """An ordered list of strips. Every value is escaped; nothing from the export is trusted.

    ``top`` is either one row per finding (``host_name``, ``owner``, ``business_unit``) or one
    row per CVE from ``top_groups`` (also ``hosts``, ``owners``, ``units``).
    """
    if top.empty:
        return ""
    items = []
    for row in top.itertuples(index=False):
        deadline = _deadline(getattr(row, "deadline", None))
        days = (deadline - as_of).days if deadline else None
        band = band_for(days) if days is not None else "far"
        cve = getattr(row, "cve", "")
        hosts = list(getattr(row, "hosts", None) or [getattr(row, "host_name", "")])
        owners = list(getattr(row, "owners", None) or [getattr(row, "owner", "") or "Unassigned"])
        units = list(getattr(row, "units", None) or [getattr(row, "business_unit", "") or ""])
        names = [short_host(host) for host in hosts]
        where = _first_and_more(names, "host")
        unit_text = units[0] if len(units) == 1 else f"{len(units)} business units"
        link = queue_link(hosts[0], cve)
        tag_html = "".join(f'<i class="{kind}">{_esc(label)}</i>' for kind, label in tags(getattr(row, "reason", "")))
        items.append(
            f'<li class="strip {band}">'
            f'<span class="s-id"><a href="{_esc(link)}" target="_self" title="Open in the fix queue">{_esc(cve)}</a>'
            f'<em title="{_esc(", ".join(names))}">{_esc(where)}</em></span>'
            f'<span class="s-owner" title="{_esc(", ".join(str(o) for o in owners))}">{_esc(_first_and_more(owners))}'
            f'<small title="{_esc(", ".join(str(u) for u in units))}">{_esc(unit_text)}</small></span>'
            f'<span class="s-when">{_esc(_when(days))}<small>{_esc(deadline.isoformat() if deadline else "")}</small></span>'
            f'<span class="s-why">{tag_html}</span>'
            "</li>"
        )
    return '<ol class="strips">' + "".join(items) + "</ol>"
