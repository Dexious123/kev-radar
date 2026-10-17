"""SLA status, compliance, aging, and the breach projection."""

from datetime import date, timedelta

import pandas as pd

from kev_radar.bod import OUTCOME_3, OUTCOME_14, OUTCOME_FSU
from kev_radar.metrics import (
    aging_buckets,
    breach_forecast,
    mean_time_to_fix,
    sla_status,
    slo_compliance,
)

AS_OF = date(2026, 10, 16)


def _frame(rows: list[dict]) -> pd.DataFrame:
    return pd.DataFrame(rows)


def test_sla_status_labels():
    assert sla_status(
        state="open", outcome=OUTCOME_3, deadline=date(2026, 10, 20), last_fixed=None, as_of=AS_OF
    ) == "Due soon"
    assert sla_status(
        state="open", outcome=OUTCOME_14, deadline=date(2026, 10, 10), last_fixed=None, as_of=AS_OF
    ) == "Overdue"
    assert sla_status(
        state="fixed", outcome=OUTCOME_14, deadline=date(2026, 10, 20), last_fixed=date(2026, 10, 12), as_of=AS_OF
    ) == "Fixed on time"
    assert sla_status(
        state="fixed", outcome=OUTCOME_14, deadline=date(2026, 10, 10), last_fixed=date(2026, 10, 12), as_of=AS_OF
    ) == "Fixed late"
    assert sla_status(
        state="open", outcome=OUTCOME_FSU, deadline=None, last_fixed=None, as_of=AS_OF
    ) == "Upgrade cycle"


def test_slo_excludes_upgrade_cycle():
    frame = _frame(
        [
            {"state": "fixed", "outcome": OUTCOME_14, "deadline": date(2026, 10, 20), "last_fixed": date(2026, 10, 1)},
            {"state": "fixed", "outcome": OUTCOME_14, "deadline": date(2026, 10, 1), "last_fixed": date(2026, 10, 5)},
            {"state": "open", "outcome": OUTCOME_3, "deadline": date(2026, 10, 1), "last_fixed": None},
            {"state": "open", "outcome": OUTCOME_14, "deadline": date(2026, 11, 1), "last_fixed": None},
            {"state": "open", "outcome": OUTCOME_FSU, "deadline": None, "last_fixed": None},
        ]
    )
    result = slo_compliance(frame, AS_OF)
    assert result["eligible"] == 4
    assert result["compliant"] == 2
    assert result["percent"] == 50.0


def test_forecast_uses_four_week_close_rate():
    rows = []
    for offset in (3, 10, 18, 25):
        rows.append(
            {
                "state": "fixed",
                "outcome": OUTCOME_14,
                "deadline": date(2026, 9, 1),
                "last_fixed": AS_OF - timedelta(days=offset),
                "first_observed": date(2026, 8, 1),
            }
        )
    for day in range(1, 6):
        rows.append(
            {
                "state": "open",
                "outcome": OUTCOME_3,
                "deadline": AS_OF + timedelta(days=day),
                "last_fixed": None,
                "first_observed": date(2026, 10, 1),
            }
        )
    rows.append(
        {
            "state": "open",
            "outcome": OUTCOME_14,
            "deadline": AS_OF - timedelta(days=2),
            "last_fixed": None,
            "first_observed": date(2026, 9, 1),
        }
    )
    forecast = breach_forecast(_frame(rows), AS_OF)
    assert forecast.closed_in_history == 4
    assert forecast.weekly_close_rate == 1.0
    assert forecast.due_in_window == 5
    assert forecast.projected_misses == 4
    assert forecast.already_overdue == 1
    assert "Projection" in forecast.statement


def test_aging_buckets_and_mttr():
    frame = _frame(
        [
            {"state": "open", "first_observed": AS_OF - timedelta(days=2), "outcome": OUTCOME_14},
            {"state": "open", "first_observed": AS_OF - timedelta(days=10), "outcome": OUTCOME_14},
            {"state": "open", "first_observed": AS_OF - timedelta(days=20), "outcome": OUTCOME_14},
            {"state": "reopened", "first_observed": AS_OF - timedelta(days=40), "outcome": OUTCOME_14},
            {"state": "fixed", "first_observed": date(2026, 8, 1), "outcome": OUTCOME_14},
            {
                "state": "fixed",
                "severity": "Critical",
                "clock_start": date(2026, 9, 1),
                "last_fixed": date(2026, 9, 11),
                "outcome": OUTCOME_14,
                "first_observed": date(2026, 9, 1),
            },
            {
                "state": "fixed",
                "severity": "High",
                "clock_start": date(2026, 9, 1),
                "last_fixed": date(2026, 9, 21),
                "outcome": OUTCOME_14,
                "first_observed": date(2026, 9, 1),
            },
        ]
    )
    aging = aging_buckets(frame, AS_OF)
    counts = dict(zip(aging["bucket"], aging["findings"], strict=True))
    assert counts == {"0–7 days": 1, "8–14 days": 1, "15–30 days": 1, "31+ days": 1}
    by_severity = mean_time_to_fix(frame, "severity")
    averages = dict(zip(by_severity["severity"], by_severity["average_days"], strict=True))
    assert averages["Critical"] == 10.0
    assert averages["High"] == 20.0


def test_time_to_fix_uses_first_seen_not_the_kev_clock():
    frame = _frame(
        [
            {
                "state": "fixed",
                "severity": "High",
                "first_observed": date(2026, 10, 1),
                "clock_start": date(2021, 12, 10),
                "last_fixed": date(2026, 10, 11),
                "outcome": OUTCOME_14,
            }
        ]
    )
    summary = mean_time_to_fix(frame)
    assert summary.iloc[0]["average_days"] == 10.0
