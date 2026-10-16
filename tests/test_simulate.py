"""What-if patching changes overdue, risk, and the breach forecast."""

from datetime import date, timedelta

import pandas as pd

from kev_radar.simulate import cves_addressed_by_kb, select_open_keys, simulate

AS_OF = date(2026, 10, 16)


def _frame() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "state": "open",
                "outcome": "3_days",
                "deadline": AS_OF - timedelta(days=2),
                "last_fixed": None,
                "first_observed": AS_OF - timedelta(days=30),
                "sla_paused": False,
                "score": 80,
                "host_name": "a.lab.invalid",
                "cve": "CVE-2016-0189",
            },
            {
                "state": "open",
                "outcome": "14_days",
                "deadline": AS_OF + timedelta(days=2),
                "last_fixed": None,
                "first_observed": AS_OF - timedelta(days=10),
                "sla_paused": False,
                "score": 30,
                "host_name": "b.lab.invalid",
                "cve": "CVE-2016-0189",
            },
            {
                "state": "open",
                "outcome": "14_days",
                "deadline": AS_OF + timedelta(days=20),
                "last_fixed": None,
                "first_observed": AS_OF - timedelta(days=5),
                "sla_paused": False,
                "score": 15,
                "host_name": "c.lab.invalid",
                "cve": "CVE-2024-0009",
            },
            {
                "state": "fixed",
                "outcome": "60_days",
                "deadline": AS_OF,
                "last_fixed": AS_OF - timedelta(days=3),
                "first_observed": AS_OF - timedelta(days=40),
                "sla_paused": False,
                "score": 10,
                "host_name": "d.lab.invalid",
                "cve": "CVE-2020-0001",
            },
        ]
    )


def test_patching_a_cve_drops_overdue_and_risk_without_inflating_history():
    frame = _frame()
    keys = select_open_keys(frame, cves=["CVE-2016-0189"])
    assert len(keys) == 2
    result = simulate(frame, AS_OF, keys)
    assert result.patched == 2
    assert result.before_overdue == 1
    assert result.after_overdue == 0
    assert result.before_due == 1
    assert result.after_due == 0
    assert result.risk_delta == 110.0
    assert result.before_misses >= result.after_misses
    # One historical close over four weeks stays 0.2/week. The what-if patches
    # are not written into that history.
    assert "0.2 findings/week" in result.before_statement
    assert "0.2 findings/week" in result.after_statement


def test_kb_selection_uses_the_snapshot():
    snapshot = {
        "cves": {
            "CVE-2016-0189": {"patches": [{"kb": "KB3154070"}, {"kb": "3156387"}]},
            "CVE-2024-0009": {"patches": [{"kb": "KB9999999"}]},
        }
    }
    assert cves_addressed_by_kb(snapshot, "3154070") == ["CVE-2016-0189"]
    assert cves_addressed_by_kb(snapshot, "KB0000000") == []
    keys = select_open_keys(_frame(), cves=cves_addressed_by_kb(snapshot, "KB3156387"))
    assert {cve for _, cve in keys} == {"CVE-2016-0189"}


def test_empty_selection_changes_nothing():
    frame = _frame()
    result = simulate(frame, AS_OF, set())
    assert result.patched == 0
    assert result.before_overdue == result.after_overdue
    assert result.before_risk == result.after_risk
