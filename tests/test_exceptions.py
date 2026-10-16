"""Exceptions register: required fields, expiry flag, and the SLA pause."""

from datetime import date, timedelta

import pandas as pd
import pytest

from kev_radar.bod import OUTCOME_3, OUTCOME_14
from kev_radar.exceptions import (
    RiskException,
    apply_exceptions,
    exceptions_from_csv,
    exceptions_from_json,
    exceptions_to_csv,
    exceptions_to_json,
    load_operator_register,
    save_operator_register,
    seed_exceptions,
)
from kev_radar.metrics import breach_forecast, slo_compliance

AS_OF = date(2026, 10, 16)


def _record(**overrides) -> RiskException:
    payload = {
        "exception_id": "EX-1",
        "host_name": "hl-pay-srv-001.lab.invalid",
        "cve": "CVE-2024-21351",
        "owner": "Priya Shah",
        "justification": "Queued for the next change window.",
        "compensating_controls": "Management VLAN only.",
        "expiry": AS_OF + timedelta(days=30),
        "approver": "Morgan Ellis",
    }
    payload.update(overrides)
    return RiskException(**payload)


def _findings() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "state": "open",
                "outcome": OUTCOME_14,
                "deadline": AS_OF - timedelta(days=2),
                "last_fixed": None,
                "first_observed": date(2026, 9, 1),
                "host_name": "hl-pay-srv-001.lab.invalid",
                "cve": "CVE-2024-21351",
                "owner": "Priya Shah",
                "score": 90,
                "sla_status": "Overdue",
            },
            {
                "state": "open",
                "outcome": OUTCOME_3,
                "deadline": AS_OF + timedelta(days=2),
                "last_fixed": None,
                "first_observed": date(2026, 10, 1),
                "host_name": "hl-pay-srv-002.lab.invalid",
                "cve": "CVE-2024-30000",
                "owner": "Luis Ortega",
                "score": 40,
                "sla_status": "Due soon",
            },
            {
                "state": "open",
                "outcome": OUTCOME_14,
                "deadline": AS_OF + timedelta(days=20),
                "last_fixed": None,
                "first_observed": date(2026, 10, 1),
                "host_name": "hl-pay-srv-003.lab.invalid",
                "cve": "CVE-2023-10000",
                "owner": "Amira Haddad",
                "score": 20,
                "sla_status": "On track",
            },
        ]
    )


def test_record_requires_every_field():
    with pytest.raises(ValueError):
        _record(justification="  ")
    with pytest.raises(ValueError):
        _record(approver="")
    record = _record()
    assert record.owner == "Priya Shah"
    assert record.compensating_controls
    assert record.pauses(AS_OF) is True


def test_expired_exception_is_flagged_and_does_not_pause():
    frame = apply_exceptions(_findings(), [_record(expiry=AS_OF - timedelta(days=1))], AS_OF)
    row = frame.iloc[0]
    assert row["exception_status"] == "Expired"
    assert bool(row["sla_paused"]) is False
    assert row["sla_status"] == "Overdue"
    assert row["sla_status_raw"] == "Overdue"


def test_active_exception_pauses_breach_counting():
    frame = apply_exceptions(_findings(), [_record()], AS_OF)
    paused = frame.iloc[0]
    assert paused["exception_status"] == "Active"
    assert paused["sla_status"] == "Exception"
    assert paused["exception_approver"] == "Morgan Ellis"
    forecast = breach_forecast(frame, AS_OF)
    assert forecast.paused == 1
    assert forecast.already_overdue == 0
    assert forecast.due_in_window == 1
    slo = slo_compliance(frame, AS_OF)
    # The paused overdue row leaves the SLO population. Due soon and on track remain.
    assert slo["eligible"] == 2
    assert slo["compliant"] == 2
    uncovered = breach_forecast(_findings(), AS_OF)
    assert uncovered.already_overdue == 1
    assert uncovered.paused == 0


def test_seed_covers_active_and_expired_with_required_fields():
    rows = []
    for index in range(6):
        rows.append(
            {
                "state": "open",
                "sla_status": "Overdue",
                "score": 100 - index,
                "host_name": f"hl-win-srv-{index:03d}.lab.invalid",
                "cve": f"CVE-2024-{index:04d}",
                "owner": "Priya Shah",
            }
        )
    records = seed_exceptions(pd.DataFrame(rows), AS_OF)
    assert len(records) == 6
    statuses = {record.status(AS_OF) for record in records}
    assert statuses == {"Active", "Expired"}
    for record in records:
        assert record.owner == "Priya Shah"
        assert record.justification.strip()
        assert record.compensating_controls.strip()
        assert record.approver.strip()
        assert isinstance(record.expiry, date)


def test_json_and_csv_round_trip(tmp_path):
    original = _record(exception_id="EX-USER-01")
    restored, errors = exceptions_from_json(exceptions_to_json([original]))
    assert errors == []
    assert restored[0].to_dict() == original.to_dict()
    from_csv, csv_errors = exceptions_from_csv(exceptions_to_csv([original]))
    assert csv_errors == []
    assert from_csv[0].cve == "CVE-2024-21351"
    display = (
        "ID,Status,Host,CVE,Owner,Approver,Expiry,Justification,Compensating controls\n"
        "EX-9,Active,host.lab.invalid,CVE-2024-0009,Ada,Morgan Ellis,2026-12-01,Reason,Control\n"
    )
    displayed, display_errors = exceptions_from_csv(display)
    assert display_errors == []
    assert displayed[0].host_name == "host.lab.invalid"
    bad, bad_errors = exceptions_from_json('{"extra": [{"cve": "CVE-2024-1"}]}')
    assert bad == []
    assert bad_errors
    path = tmp_path / "exceptions.json"
    save_operator_register({"extra": [original.to_dict()], "removed": ["EX-2604-01"], "seq": 4}, path)
    loaded = load_operator_register(path)
    assert loaded["seq"] == 4
    assert loaded["removed"] == ["EX-2604-01"]
    assert loaded["extra"][0]["cve"] == "CVE-2024-21351"
    assert load_operator_register(tmp_path / "missing.json")["extra"] == []
