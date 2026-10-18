"""Executive overview: trend, burndown projection, and the weekly fix list."""

from datetime import date, timedelta

import pandas as pd

from kev_radar.overview import fix_reason, headline, projected_burndown, risk_trend, top_groups, top_to_fix

AS_OF = date(2026, 10, 16)


def _frame() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "state": "open",
                "outcome": "3_days",
                "outcome_label": "3 days",
                "deadline": AS_OF - timedelta(days=4),
                "days_left": -4,
                "first_observed": AS_OF - timedelta(days=40),
                "last_fixed": None,
                "sla_status": "Overdue",
                "sla_paused": False,
                "sla_status_raw": "Overdue",
                "score": 90,
                "host_name": "a.lab.invalid",
                "cve": "CVE-2024-0001",
                "owner": "Ada",
                "business_unit": "Payments",
                "exposed": True,
                "in_kev": True,
                "ransomware": True,
                "forensics_required": True,
                "epss": 0.8,
                "decision_path": "KEV=Yes",
            },
            {
                "state": "open",
                "outcome": "14_days",
                "outcome_label": "14 days",
                "deadline": AS_OF + timedelta(days=3),
                "days_left": 3,
                "first_observed": AS_OF - timedelta(days=10),
                "last_fixed": None,
                "sla_status": "Due soon",
                "sla_paused": False,
                "sla_status_raw": "Due soon",
                "score": 40,
                "host_name": "b.lab.invalid",
                "cve": "CVE-2024-0002",
                "owner": "Ben",
                "business_unit": "Claims",
                "exposed": False,
                "in_kev": False,
                "ransomware": False,
                "forensics_required": False,
                "epss": 0.05,
                "decision_path": "KEV=No",
            },
            {
                "state": "open",
                "outcome": "14_days",
                "outcome_label": "14 days",
                "deadline": AS_OF - timedelta(days=1),
                "days_left": -1,
                "first_observed": AS_OF - timedelta(days=20),
                "last_fixed": None,
                "sla_status": "Exception",
                "sla_paused": True,
                "sla_status_raw": "Overdue",
                "score": 70,
                "host_name": "c.lab.invalid",
                "cve": "CVE-2024-0003",
                "owner": "Cho",
                "business_unit": "Identity",
                "exposed": False,
                "in_kev": True,
                "ransomware": False,
                "forensics_required": False,
                "epss": 0.2,
                "decision_path": "paused",
            },
            {
                "state": "fixed",
                "outcome": "60_days",
                "outcome_label": "60 days",
                "deadline": AS_OF - timedelta(days=1),
                "days_left": None,
                "first_observed": AS_OF - timedelta(days=50),
                "last_fixed": AS_OF - timedelta(days=2),
                "sla_status": "Fixed on time",
                "sla_paused": False,
                "sla_status_raw": "Fixed on time",
                "score": 10,
                "host_name": "d.lab.invalid",
                "cve": "CVE-2024-0004",
                "owner": "Dee",
                "business_unit": "Payments",
                "exposed": False,
                "in_kev": False,
                "ransomware": False,
                "forensics_required": False,
                "epss": 0.01,
                "decision_path": "fixed",
            },
        ]
    )


def test_top_ten_skips_the_paused_row_and_explains_the_first():
    ranked = top_to_fix(_frame(), AS_OF, limit=10)
    assert list(ranked["cve"]) == ["CVE-2024-0001", "CVE-2024-0002"]
    reason = ranked.iloc[0]["reason"]
    assert "4 days overdue" in reason
    assert "forensic triage" in reason
    assert "ransomware" in reason
    assert "EPSS 80%" in reason


def test_fix_reason_for_a_due_soon_row():
    row = _frame().iloc[1]
    text = fix_reason(row, AS_OF)
    assert text.startswith("due in 3 days")
    assert "14 days" in text


def test_trend_latest_overdue_matches_the_paused_kpi():
    trend = risk_trend(_frame(), AS_OF, weeks=4)
    assert list(trend["week_ending"])[-1] == AS_OF.isoformat()
    numbers = headline(_frame(), AS_OF)
    assert int(trend.iloc[-1]["overdue"]) == numbers["overdue"]
    assert numbers["overdue"] == 1
    assert numbers["risk"] == 200.0
    burn = projected_burndown(numbers["overdue"], numbers["weekly_close_rate"], AS_OF, weeks=2)
    assert burn.iloc[0]["kind"] == "actual"
    assert burn.iloc[-1]["kind"] == "projection"
    assert int(burn.iloc[-1]["overdue"]) <= numbers["overdue"]

def test_top_groups_lists_each_cve_once_with_every_host():
    frame = _frame()
    twin = frame.iloc[[0]].copy()
    twin["host_name"] = "c.lab.invalid"
    twin["owner"] = "Cy"
    twin["score"] = 10
    twin["days_left"] = 5
    twin["sla_status"] = "Due soon"
    frame = pd.concat([frame, twin], ignore_index=True)
    groups = top_groups(frame, AS_OF, limit=10)
    assert groups["cve"].tolist().count("CVE-2024-0001") == 1
    first = groups.iloc[0]
    assert first["cve"] == "CVE-2024-0001" and first["host_name"] == "a.lab.invalid"
    assert first["hosts"] == ["a.lab.invalid", "c.lab.invalid"]
    assert first["owners"] == ["Ada", "Cy"]
    limited = top_groups(frame, AS_OF, limit=1)
    assert len(limited) == 1 and limited.iloc[0]["hosts"] == ["a.lab.invalid", "c.lab.invalid"]
    assert top_groups(frame.iloc[0:0], AS_OF).empty
