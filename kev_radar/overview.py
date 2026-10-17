"""Executive overview: KPIs, an 8-week risk trend, and this week's fix list.

The overdue series counts findings that were already open and past their
deadline at each week ending. It does not replay historical exceptions.
The latest point is adjusted by today's active pauses so it matches the
SLA overdue count on the console.
"""

from __future__ import annotations

from datetime import date, timedelta

import pandas as pd

from kev_radar.metrics import _as_date, breach_forecast, is_open


def portfolio_risk(findings: pd.DataFrame) -> float:
    """Sum of priority scores on open findings, including paused ones."""
    if findings.empty or "score" not in findings.columns:
        return 0.0
    open_rows = findings[findings["state"].map(is_open)]
    if open_rows.empty:
        return 0.0
    return round(float(open_rows["score"].fillna(0).sum()), 1)


def _open_at(row, end: date) -> bool:
    first = _as_date(getattr(row, "first_observed", None))
    if first is None or first > end:
        return False
    state = getattr(row, "state", "open")
    last_fixed = _as_date(getattr(row, "last_fixed", None))
    if not is_open(state) and last_fixed is not None and last_fixed <= end:
        return False
    if not is_open(state) and last_fixed is None:
        return False
    return True


def _overdue_at(row, end: date) -> bool:
    if not _open_at(row, end):
        return False
    outcome = getattr(row, "outcome", None)
    deadline = _as_date(getattr(row, "deadline", None))
    if deadline is None or outcome in {"fix_on_upgrade", "Fix on system upgrade"}:
        return False
    return deadline < end


def risk_trend(findings: pd.DataFrame, as_of: date, *, weeks: int = 8) -> pd.DataFrame:
    """Weekly open count, raw overdue count, and open risk score."""
    rows: list[dict] = []
    records = [] if findings.empty else list(findings.itertuples(index=False))
    for offset in range(weeks - 1, -1, -1):
        end = as_of - timedelta(days=7 * offset)
        open_count = 0
        overdue = 0
        risk = 0.0
        for row in records:
            if not _open_at(row, end):
                continue
            open_count += 1
            risk += float(getattr(row, "score", 0) or 0)
            if _overdue_at(row, end):
                overdue += 1
        rows.append(
            {
                "week_ending": end.isoformat(),
                "open_findings": open_count,
                "overdue": overdue,
                "risk_score": round(risk, 1),
            }
        )
    frame = pd.DataFrame(rows)
    if frame.empty:
        return frame
    # The console's overdue KPI excludes today's active exceptions. Earlier
    # weeks do not have a pause history, so only the latest point is aligned.
    paused = 0
    if not findings.empty and "sla_paused" in findings.columns:
        paused = int(
            (
                findings["state"].map(is_open)
                & findings["sla_paused"].map(bool)
                & findings["sla_status_raw"].fillna("").eq("Overdue")
            ).sum()
        ) if "sla_status_raw" in findings.columns else int(
            (findings["state"].map(is_open) & findings["sla_paused"].map(bool)).sum()
        )
    if paused and len(frame):
        frame.loc[frame.index[-1], "overdue"] = max(0, int(frame.iloc[-1]["overdue"]) - paused)
    return frame


def projected_burndown(
    overdue_now: int,
    weekly_close_rate: float,
    as_of: date,
    *,
    weeks: int = 4,
) -> pd.DataFrame:
    """Straight-line burn of today's overdue stock at the recent close rate.

    New findings that will become overdue are not in this line. The label
    in the UI says so.
    """
    remaining = float(overdue_now)
    rows = [{"week_ending": as_of.isoformat(), "overdue": int(round(remaining)), "kind": "actual"}]
    for step in range(1, weeks + 1):
        remaining = max(0.0, remaining - weekly_close_rate)
        rows.append(
            {
                "week_ending": (as_of + timedelta(days=7 * step)).isoformat(),
                "overdue": int(round(remaining)),
                "kind": "projection",
            }
        )
    return pd.DataFrame(rows)


def fix_reason(row, as_of: date) -> str:
    """One sentence a patching lead can read without opening the row."""
    parts: list[str] = []
    status = str(getattr(row, "sla_status", "") or "")
    raw = str(getattr(row, "sla_status_raw", "") or "")
    days = getattr(row, "days_left", None)
    try:
        days_int = None if days is None or pd.isna(days) else int(days)
    except (TypeError, ValueError):
        days_int = None
    if status == "Overdue" and days_int is not None:
        late = abs(days_int)
        parts.append(f"{late} day{'' if late == 1 else 's'} overdue")
    elif status == "Due soon" and days_int is not None:
        parts.append("due today" if days_int == 0 else f"due in {days_int} day{'' if days_int == 1 else 's'}")
    elif status == "Exception":
        parts.append(f"exception pauses a {raw.lower() or 'open'} finding")
    elif status:
        parts.append(status.lower())
    label = str(getattr(row, "outcome_label", "") or "")
    if label:
        parts.append(label)
    if bool(getattr(row, "forensics_required", False)):
        parts.append("forensic triage required")
    if bool(getattr(row, "ransomware", False)):
        parts.append("known ransomware use")
    if bool(getattr(row, "exposed", False)):
        parts.append("publicly exposed")
    epss = getattr(row, "epss", None)
    try:
        if epss is not None and not pd.isna(epss) and float(epss) >= 0.3:
            parts.append(f"EPSS {float(epss):.0%}")
    except (TypeError, ValueError):
        pass
    if not parts:
        return "Open finding with no deadline detail."
    return " · ".join(parts)


def _rank(status: str) -> int:
    if status == "Overdue":
        return 0
    if status == "Due soon":
        return 1
    if status == "On track":
        return 2
    return 3


def top_to_fix(findings: pd.DataFrame, as_of: date, *, limit: int = 10) -> pd.DataFrame:
    """Open findings to patch this week, excluding active exceptions.

    Overdue rows come first, then rows due within 7 days, then the highest
    priority score.
    """
    columns = ["host_name", "cve", "owner", "business_unit", "score", "sla_status", "reason"]
    if findings.empty:
        return pd.DataFrame(columns=columns)
    open_rows = findings[findings["state"].map(is_open)].copy()
    if "sla_paused" in open_rows.columns:
        open_rows = open_rows[~open_rows["sla_paused"].map(bool)]
    if open_rows.empty:
        return pd.DataFrame(columns=columns)
    open_rows["_rank"] = open_rows["sla_status"].map(_rank)
    open_rows = open_rows.sort_values(
        ["_rank", "score", "days_left"],
        ascending=[True, False, True],
        na_position="last",
    ).head(limit)
    rows = []
    for record in open_rows.itertuples(index=False):
        rows.append(
            {
                "host_name": record.host_name,
                "cve": record.cve,
                "owner": getattr(record, "owner", ""),
                "business_unit": getattr(record, "business_unit", ""),
                "score": round(float(getattr(record, "score", 0) or 0), 1),
                "sla_status": record.sla_status,
                "deadline": getattr(record, "deadline", None),
                "decision_path": getattr(record, "decision_path", ""),
                "reason": fix_reason(record, as_of),
            }
        )
    return pd.DataFrame(rows)


def headline(findings: pd.DataFrame, as_of: date) -> dict:
    """Numbers the overview cards show."""
    forecast = breach_forecast(findings, as_of)
    open_count = 0 if findings.empty else int(findings["state"].map(is_open).sum())
    return {
        "open": open_count,
        "overdue": int(forecast.already_overdue),
        "due_soon": int(forecast.due_in_window),
        "projected_misses": int(forecast.projected_misses),
        "risk": portfolio_risk(findings),
        "weekly_close_rate": float(forecast.weekly_close_rate),
        "forecast": forecast,
    }
