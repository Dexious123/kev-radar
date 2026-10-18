"""The deadline radar: every open finding with a deadline, placed by time left and business unit.

Distance from the center is time left until the BOD 26-04 deadline. The inner disc
is past due, then due within 7 days, within 30 days, and later. Each slice is a
business unit. Inside its slice and its band, a dot's exact spot comes from a stable
hash of host and CVE, so a finding always lands in the same place; only the slice and
the distance carry meaning. Each dot's animation delay is set from its angle, so it
brightens as the sweep passes over it. A finding the scanner first saw in the latest
scan wears an open ring, like a new contact on a scope.

Each dot carries its details as escaped data attributes. ``radar.js`` (``RADAR_SCRIPT``)
turns them into a data block for the dot nearest the pointer, a tap, or the arrow keys.
"""

from __future__ import annotations

import hashlib
import html
import math
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import pandas as pd

from kev_radar.metrics import is_open

RADAR_SCRIPT = Path(__file__).with_name("radar.js").read_text(encoding="utf-8")

RADIUS = 165
# Wide and short: slice labels sit beside the rings, so only the sides need room.
WIDTH = 610
HEIGHT = 2 * RADIUS + 56
CX, CY = WIDTH / 2, HEIGHT / 2
SWEEP_SECONDS = 8.0
MAX_DOTS = 700
MAX_SLICES = 8

# Outer edge of each band, as a fraction of RADIUS. Dots stay inside their band.
BANDS = (
    ("past", "Past due", 0.40),
    ("near", "7 days", 0.58),
    ("soon", "30 days", 0.77),
    ("far", "Later", 1.0),
)


@dataclass
class Radar:
    svg: str
    counts: dict[str, int] = field(default_factory=dict)
    plotted: int = 0


def _unit(text: str) -> float:
    """A stable number in [0, 1) for a key, so positions do not move between runs."""
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") / 2**64


def band_for(days: int) -> str:
    if days < 0:
        return "past"
    if days <= 7:
        return "near"
    if days <= 30:
        return "soon"
    return "far"


def radial_fraction(days: int, key: str) -> float:
    """Distance from the center as a fraction of RADIUS. Less time left is closer in."""
    wobble = (_unit("r:" + key) - 0.5) * 0.02
    if days < 0:
        # Longest overdue sits nearest the center, on a log scale so a two-year-old
        # backlog does not flatten everything overdue this week.
        depth = min(1.0, math.log1p(-days) / math.log1p(1000))
        value = 0.38 - 0.30 * depth
        low, high = 0.06, 0.39
    elif days <= 7:
        value, low, high = 0.42 + 0.14 * (days / 7), 0.41, 0.57
    elif days <= 30:
        value, low, high = 0.60 + 0.15 * ((days - 8) / 22), 0.59, 0.76
    else:
        value = 0.80 + 0.17 * min(1.0, math.log1p(days - 31) / math.log1p(335))
        low, high = 0.79, 0.98
    return min(high, max(low, value + wobble))


def _slices(units: list[str]) -> list[str]:
    """Business units in a fixed order, folding the tail into Other past MAX_SLICES."""
    counts = pd.Series(units).value_counts()
    if len(counts) <= MAX_SLICES:
        return sorted(counts.index)
    keep = sorted(counts.index[: MAX_SLICES - 1])
    return keep + ["Other"]


def _point(angle_deg: float, distance: float) -> tuple[float, float]:
    """Angle in degrees clockwise from twelve o'clock; distance in pixels."""
    theta = math.radians(angle_deg)
    return CX + distance * math.sin(theta), CY - distance * math.cos(theta)


def _when(days: int) -> str:
    if days < 0:
        late = -days
        return f"{late:,} day{'' if late == 1 else 's'} past due"
    if days == 0:
        return "Due today"
    return f"Due in {days:,} day{'' if days == 1 else 's'}"


def _day(value: object) -> date | None:
    if value is None or (not isinstance(value, date) and pd.isna(value)):
        return None
    if isinstance(value, pd.Timestamp):
        return value.date()
    return value if isinstance(value, date) else None


def build_radar(frame: pd.DataFrame, as_of: date, *, new_on: date | None = None, mini: bool = False) -> Radar:
    """``new_on`` is the latest scan day; findings first seen that day get a ring.

    ``mini`` crops the view to the scope for the slim page header, where the radar is a
    button that opens the enlarged view; ``data-full`` keeps the full view for that.
    """
    rows = []
    if not frame.empty:
        for row in frame.itertuples(index=False):
            if not is_open(getattr(row, "state", "open")):
                continue
            if bool(getattr(row, "sla_paused", False)):
                continue
            deadline = getattr(row, "deadline", None)
            if deadline is None or (isinstance(deadline, float) and math.isnan(deadline)) or pd.isna(deadline):
                continue
            if isinstance(deadline, pd.Timestamp):
                deadline = deadline.date()
            rows.append(
                {
                    "days": (deadline - as_of).days,
                    "deadline": deadline,
                    "unit": str(getattr(row, "business_unit", None) or "Unassigned"),
                    "cve": str(getattr(row, "cve", "")),
                    "host": str(getattr(row, "host_name", "")),
                    "owner": str(getattr(row, "owner", None) or "Unassigned"),
                    "score": float(getattr(row, "score", 0) or 0),
                    "new": new_on is not None and _day(getattr(row, "first_observed", None)) == new_on,
                }
            )
    counts = {key: 0 for key, _, _ in BANDS}
    for item in rows:
        counts[band_for(item["days"])] += 1
    counts["new"] = sum(1 for item in rows if item["new"])
    if len(rows) > MAX_DOTS:
        # New contacts always stay on the scope, whatever their score.
        rows = sorted(rows, key=lambda item: (item["new"], item["score"]), reverse=True)[:MAX_DOTS]

    slices = _slices([item["unit"] for item in rows]) if rows else []
    span = 360.0 / len(slices) if slices else 360.0
    index = {name: i for i, name in enumerate(slices)}

    parts: list[str] = []
    total = sum(counts[key] for key, _, _ in BANDS)
    summary = (
        f"{total} open findings with a deadline: {counts['past']} past due, {counts['near']} due within 7 days, "
        f"{counts['soon']} within 30 days, {counts['far']} later. Slices are business units."
    )
    if counts["new"]:
        summary += f" {counts['new']} first seen in the latest scan."
    if mini:
        summary += " Select the radar to enlarge it."
    else:
        summary += (
            " Arrow keys step through the findings, most overdue first; Enter opens the selected finding in the fix "
            "queue, or enlarges the radar when none is selected; Escape closes the details."
        )
    full = f"0 0 {WIDTH} {HEIGHT:.0f}"
    edge = RADIUS + 8
    view = f"{CX - edge:.0f} {CY - edge:.0f} {2 * edge} {2 * edge}" if mini else full
    parts.append(
        f'<svg class="radar" viewBox="{view}" data-full="{full}" role="group" tabindex="0" '
        'aria-labelledby="kr-t" aria-describedby="kr-d">'
        '<title id="kr-t">Deadline radar</title>'
        f'<desc id="kr-d">{html.escape(summary)}</desc>'
        '<defs><linearGradient id="kr-sweep" x1="0" y1="0" x2="1" y2="0">'
        '<stop offset="0" stop-color="#63D3E3" stop-opacity="0"/>'
        '<stop offset="1" stop-color="#63D3E3" stop-opacity="0.30"/>'
        "</linearGradient></defs>"
    )
    for _, label, edge in BANDS:
        parts.append(f'<circle class="ring" cx="{CX}" cy="{CY}" r="{edge * RADIUS:.1f}"/>')
    for i in range(len(slices)):
        x, y = _point(i * span, RADIUS)
        parts.append(f'<line class="spoke" x1="{CX}" y1="{CY}" x2="{x:.1f}" y2="{y:.1f}"/>')
    for _, label, edge in BANDS:
        parts.append(
            f'<text class="band-label" x="{CX + 5}" y="{CY - edge * RADIUS + 13:.1f}">{html.escape(label)}</text>'
        )
    for i, name in enumerate(slices):
        mid = i * span + span / 2
        x, y = _point(mid, RADIUS + 20)
        sine = math.sin(math.radians(mid))
        anchor = "start" if sine > 0.2 else "end" if sine < -0.2 else "middle"
        parts.append(f'<text class="slice-label" x="{x:.1f}" y="{y:.1f}" text-anchor="{anchor}">{html.escape(name)}</text>')

    lead = _point(0, RADIUS)
    trail = _point(-48, RADIUS)
    # The rotation origin is pinned in user units: a percentage origin follows the viewBox, and the
    # enlarged view crops the viewBox to the scope.
    parts.append(
        f'<g class="sweep" style="transform-origin:{CX:.0f}px {CY:.0f}px">'
        f'<path d="M{CX} {CY} L{trail[0]:.1f} {trail[1]:.1f} A{RADIUS} {RADIUS} 0 0 1 {lead[0]:.1f} {lead[1]:.1f} Z" fill="url(#kr-sweep)"/>'
        f'<line class="beam" x1="{CX}" y1="{CY}" x2="{lead[0]:.1f}" y2="{lead[1]:.1f}"/>'
        "</g>"
    )
    for item in rows:
        key = f"{item['host']}|{item['cve']}"
        slot = index.get(item["unit"], index.get("Other", 0))
        angle = slot * span + span * (0.08 + 0.84 * _unit("a:" + key))
        x, y = _point(angle, radial_fraction(item["days"], key) * RADIUS)
        size = 1.3 + 2.0 * min(1.0, max(0.0, item["score"] / 100.0))
        delay = angle / 360.0 * SWEEP_SECONDS - SWEEP_SECONDS
        if item["new"]:
            parts.append(f'<circle class="contact" cx="{x:.1f}" cy="{y:.1f}" r="{size + 3.2:.1f}"/>')
        deadline = item["deadline"]
        data = {
            "cve": item["cve"],
            "host": item["host"],
            "owner": item["owner"],
            "unit": item["unit"],
            "when": _when(item["days"]),
            "due": f"{deadline:%b} {deadline.day}, {deadline.year}",
            "days": str(item["days"]),
        }
        if item["new"]:
            data["new"] = "1"
        attributes = " ".join(f'data-{key}="{html.escape(value, quote=True)}"' for key, value in data.items())
        parts.append(
            f'<circle class="dot {band_for(item["days"])}" cx="{x:.1f}" cy="{y:.1f}" r="{size:.1f}" '
            f'style="animation-delay:{delay:.2f}s" {attributes}/>'
        )
    parts.append(f'<circle class="core" cx="{CX}" cy="{CY}" r="2.5"/>')
    parts.append("</svg>")
    return Radar(svg="".join(parts), counts=counts, plotted=len(rows))
