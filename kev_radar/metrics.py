"""SLA countdown, time to fix, aging, and a simple breach projection.

"Fix on system upgrade" findings have no day-count deadline, so they stay out
of the compliance percentage and the breach projection.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta

import pandas as pd

from kev_radar.bod import OUTCOME_FSU

OPEN_STATES = {"open", "reopened"}
AGING_LABELS = ("0–7 days", "8–14 days", "15–30 days", "30+ days")


def is_open(state: object) -> bool:
    return str(state).strip().lower() in OPEN_STATES


def sla_status(
    *,
    state: object,
    outcome: object,
    deadline: date | None,
    last_fixed: date | None,
    as_of: date,
) -> str:
    if outcome == OUTCOME_FSU or (isinstance(outcome, str) and outcome == "Fix on system upgrade"):
        return "Upgrade cycle"
    if deadline is None:
        return "No clock"
    open_finding = is_open(state)
    if not open_finding:
        if last_fixed is None:
            return "No clock"
        return "Fixed on time" if last_fixed <= deadline else "Fixed late"
    remaining = (deadline - as_of).days
    if remaining < 0:
        return "Overdue"
    if remaining <= 7:
        return "Due soon"
    return "On track"


def days_left(deadline: date | None, as_of: date, outcome: object) -> int | None:
    if outcome in {OUTCOME_FSU, "Fix on system upgrade"} or deadline is None:
        return None
    return (deadline - as_of).days


@dataclass(frozen=True)
class BreachForecast:
    history_days: int
    window_days: int
    closed_in_history: int
    weekly_close_rate: float
    due_in_window: int
    projected_misses: int
    already_overdue: int
    paused: int
    statement: str


def _as_date(value: object) -> date | None:
    if value is None or value is pd.NaT:
        return None
    try:
        if pd.isna(value):
            return None
    except TypeError:
        pass
    if isinstance(value, date) and not isinstance(value, pd.Timestamp):
        return value
    if isinstance(value, pd.Timestamp):
        return value.date()
    parsed = pd.to_datetime(value, errors="coerce")
    if pd.isna(parsed):
        return None
    return parsed.date()


def breach_forecast(
    findings: pd.DataFrame,
    as_of: date,
    *,
    history_days: int = 28,
    window_days: int = 7,
) -> BreachForecast:
    """Project misses from the last four weeks of closes.

    The projection is ``max(0, findings due in the next window − closes
    expected at the recent weekly rate)``. It is a rate sketch, not a model.
    """
    if findings.empty:
        statement = "No findings to project."
        return BreachForecast(
            history_days=history_days,
            window_days=window_days,
            closed_in_history=0,
            weekly_close_rate=0.0,
            due_in_window=0,
            projected_misses=0,
            already_overdue=0,
            paused=0,
            statement=statement,
        )

    history_start = as_of - timedelta(days=history_days)
    window_end = as_of + timedelta(days=window_days)
    closed = 0
    due = 0
    overdue = 0
    paused = 0
    for row in findings.itertuples(index=False):
        outcome = getattr(row, "outcome", None)
        deadline = _as_date(getattr(row, "deadline", None))
        if outcome in {OUTCOME_FSU, "Fix on system upgrade"} or deadline is None:
            continue
        state = getattr(row, "state", "open")
        last_fixed = _as_date(getattr(row, "last_fixed", None))
        if not is_open(state):
            if last_fixed is not None and history_start < last_fixed <= as_of:
                closed += 1
            continue
        if bool(getattr(row, "sla_paused", False)):
            paused += 1
            continue
        if deadline < as_of:
            overdue += 1
        elif deadline <= window_end:
            due += 1

    weeks = history_days / 7
    weekly = closed / weeks if weeks else 0.0
    expected_closes = weekly * (window_days / 7)
    misses = int(round(max(0.0, due - expected_closes)))
    # Keep the displayed miss count from exceeding the queue.
    misses = min(misses, due)
    rate_text = f"{weekly:.1f} finding{'s' if abs(weekly - 1) > 0.05 else ''}/week"
    statement = (
        f"Projection, not a prediction. At the last {history_days // 7} weeks' "
        f"close rate ({rate_text}), about {misses} of the {due} findings due "
        f"in the next {window_days} days will miss their BOD 26-04 deadline. "
        f"{overdue} {'are' if overdue != 1 else 'is'} already overdue and "
        f"{'are' if overdue != 1 else 'is'} not part of that projection."
    )
    if paused:
        statement += (
            f" {paused} open {'findings are' if paused != 1 else 'finding is'} covered by an "
            "active exception, so they are left out of the overdue count and this projection."
        )
    return BreachForecast(
        history_days=history_days,
        window_days=window_days,
        closed_in_history=closed,
        weekly_close_rate=round(weekly, 2),
        due_in_window=due,
        projected_misses=misses,
        already_overdue=overdue,
        paused=paused,
        statement=statement,
    )


def _aging_bucket(days_open: int) -> str:
    if days_open <= 7:
        return AGING_LABELS[0]
    if days_open <= 14:
        return AGING_LABELS[1]
    if days_open <= 30:
        return AGING_LABELS[2]
    return AGING_LABELS[3]


def aging_buckets(findings: pd.DataFrame, as_of: date) -> pd.DataFrame:
    """Open-finding age from first seen, in four aging buckets."""
    counts = {label: 0 for label in AGING_LABELS}
    if findings.empty:
        return pd.DataFrame({"bucket": list(counts), "findings": list(counts.values())})
    for row in findings.itertuples(index=False):
        if not is_open(getattr(row, "state", "open")):
            continue
        first = _as_date(getattr(row, "first_observed", None))
        if first is None:
            continue
        counts[_aging_bucket(max(0, (as_of - first).days))] += 1
    return pd.DataFrame({"bucket": list(counts), "findings": list(counts.values())})


def time_to_fix_days(first_observed: object, last_fixed: object) -> int | None:
    """Days from scanner first-seen to last fixed.

    This is the operational time to fix. The BOD clock can start earlier, on
    the KEV addition date, and that earlier date is what makes a finding
    overdue. It is not the team's repair time.
    """
    start = _as_date(first_observed)
    fixed = _as_date(last_fixed)
    if start is None or fixed is None:
        return None
    return max(0, (fixed - start).days)


def mean_time_to_fix(findings: pd.DataFrame, group_by: str | None = None) -> pd.DataFrame:
    """Average days from first seen to last fixed, for fixed findings."""
    if findings.empty:
        columns = ["findings", "average_days"]
        if group_by:
            columns = [group_by, *columns]
        return pd.DataFrame(columns=columns)
    rows: list[dict] = []
    for record in findings.itertuples(index=False):
        if is_open(getattr(record, "state", "open")):
            continue
        days = time_to_fix_days(
            getattr(record, "first_observed", None),
            getattr(record, "last_fixed", None),
        )
        if days is None:
            continue
        group = getattr(record, group_by, "All") if group_by else "All"
        rows.append({group_by or "group": group, "days": days})
    if not rows:
        columns = ["findings", "average_days"]
        if group_by:
            columns = [group_by, *columns]
        return pd.DataFrame(columns=columns)
    frame = pd.DataFrame(rows)
    key = group_by or "group"
    summary = (
        frame.groupby(key, dropna=False)["days"]
        .agg(findings="count", average_days="mean")
        .reset_index()
    )
    summary["average_days"] = summary["average_days"].round(1)
    if group_by is None:
        summary = summary.drop(columns=["group"])
    return summary.sort_values("average_days", ascending=False).reset_index(drop=True)


def slo_compliance(findings: pd.DataFrame, as_of: date) -> dict[str, float | int]:
    """Share of clocked findings that are still inside the deadline or were fixed in time."""
    eligible = 0
    compliant = 0
    if not findings.empty:
        for row in findings.itertuples(index=False):
            outcome = getattr(row, "outcome", None)
            deadline = _as_date(getattr(row, "deadline", None))
            if outcome in {OUTCOME_FSU, "Fix on system upgrade"} or deadline is None:
                continue
            if bool(getattr(row, "sla_paused", False)):
                continue
            eligible += 1
            state = getattr(row, "state", "open")
            last_fixed = _as_date(getattr(row, "last_fixed", None))
            if is_open(state):
                if as_of <= deadline:
                    compliant += 1
            elif last_fixed is not None and last_fixed <= deadline:
                compliant += 1
    percent = round(100.0 * compliant / eligible, 1) if eligible else 0.0
    return {"eligible": eligible, "compliant": compliant, "percent": percent}


def burndown(findings: pd.DataFrame, as_of: date, weeks: int = 8) -> pd.DataFrame:
    """Open findings at each of the last ``weeks`` week-ending dates."""
    points: list[dict] = []
    for offset in range(weeks - 1, -1, -1):
        end = as_of - timedelta(days=7 * offset)
        open_count = 0
        if not findings.empty:
            for row in findings.itertuples(index=False):
                first = _as_date(getattr(row, "first_observed", None))
                if first is None or first > end:
                    continue
                state = getattr(row, "state", "open")
                last_fixed = _as_date(getattr(row, "last_fixed", None))
                if not is_open(state) and last_fixed is not None and last_fixed <= end:
                    continue
                if not is_open(state) and last_fixed is None:
                    continue
                open_count += 1
        points.append({"week_ending": end.isoformat(), "open_findings": open_count})
    return pd.DataFrame(points)


def outcome_mix(findings: pd.DataFrame) -> pd.DataFrame:
    if findings.empty or "outcome_label" not in findings.columns:
        return pd.DataFrame(columns=["outcome", "findings"])
    counts = (
        findings.groupby("outcome_label", dropna=False)
        .size()
        .reset_index(name="findings")
        .rename(columns={"outcome_label": "outcome"})
        .sort_values("findings", ascending=False)
    )
    return counts.reset_index(drop=True)
