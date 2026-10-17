"""The top of the queue as flight strips: one row per finding, in the order to work it.

Air traffic controllers sequence arrivals on printed strips with a colored edge. Here
the edge is the deadline band (past due, due within 7 days, later), the fixed-width
columns carry the identifiers a patching lead copies into a ticket, and the last
column says why the finding is on the list.
"""

from __future__ import annotations

import html
import math
import re
from datetime import date

import pandas as pd

from kev_radar.radar import band_for


def _deadline(value) -> date | None:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return None
    if isinstance(value, pd.Timestamp):
        return value.date()
    return value if isinstance(value, date) else None


# The strip already shows how late a finding is, so the reason drops its timing phrase.
_TIMING = re.compile(r"^(\d+ days? overdue|due in \d+ days?|due today)$", re.IGNORECASE)


def _why(reason) -> str:
    parts = [part.strip() for part in str(reason or "").split("·")]
    return ", ".join(part for part in parts if part and not _TIMING.match(part))


def _esc(value) -> str:
    return html.escape(str(value if value is not None else ""))


def _when(days: int | None) -> str:
    if days is None:
        return "No fixed deadline"
    if days < 0:
        late = -days
        return f"{late} day{'' if late == 1 else 's'} past due"
    if days == 0:
        return "Due today"
    return f"Due in {days} day{'' if days == 1 else 's'}"


def render_strips(top: pd.DataFrame, as_of: date) -> str:
    """An ordered list of strips. Every value is escaped; nothing from the export is trusted."""
    if top.empty:
        return ""
    items = []
    for row in top.itertuples(index=False):
        deadline = _deadline(getattr(row, "deadline", None))
        days = (deadline - as_of).days if deadline else None
        band = band_for(days) if days is not None else "far"
        items.append(
            f'<li class="strip {band}">'
            f'<span class="s-id"><b>{_esc(getattr(row, "cve", ""))}</b>{_esc(getattr(row, "host_name", ""))}</span>'
            f'<span class="s-owner">{_esc(getattr(row, "owner", "") or "Unassigned")}'
            f'<small>{_esc(getattr(row, "business_unit", "") or "")}</small></span>'
            f'<span class="s-when">{_esc(_when(days))}<small>{_esc(deadline.isoformat() if deadline else "")}</small></span>'
            f'<span class="s-why">{_esc(_why(getattr(row, "reason", "")))}</span>'
            "</li>"
        )
    return '<ol class="strips">' + "".join(items) + "</ol>"
