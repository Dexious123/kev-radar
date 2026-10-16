"""BOD 26-04 decision table, fallbacks, and clock start."""

from datetime import date, timedelta

import pytest

from kev_radar.bod import (
    DECISION_TABLE,
    OUTCOME_3,
    OUTCOME_3F,
    OUTCOME_14,
    OUTCOME_60,
    OUTCOME_FSU,
    bod_deadline,
    days_remaining,
    lookup_outcome,
)

# CERT/CC cisa:DT_BOD2604:1.0.0, rows 0–15.
EXPECTED = [
    (False, False, False, "partial", OUTCOME_FSU),
    (True, False, False, "partial", OUTCOME_14),
    (False, True, False, "partial", OUTCOME_60),
    (False, False, True, "partial", OUTCOME_60),
    (False, False, False, "total", OUTCOME_FSU),
    (True, True, False, "partial", OUTCOME_14),
    (True, False, True, "partial", OUTCOME_14),
    (False, True, True, "partial", OUTCOME_14),
    (True, False, False, "total", OUTCOME_14),
    (False, True, False, "total", OUTCOME_14),
    (False, False, True, "total", OUTCOME_60),
    (True, True, True, "partial", OUTCOME_3),
    (True, True, False, "total", OUTCOME_3F),
    (True, False, True, "total", OUTCOME_3F),
    (False, True, True, "total", OUTCOME_3),
    (True, True, True, "total", OUTCOME_3F),
]


@pytest.mark.parametrize(
    ("in_kev", "exposed", "automatable", "impact", "outcome"),
    EXPECTED,
)
def test_all_sixteen_paths(in_kev, exposed, automatable, impact, outcome):
    assert lookup_outcome(in_kev, exposed, automatable, impact) == outcome


def test_table_covers_every_combination():
    assert len(DECISION_TABLE) == 16
    assert len(EXPECTED) == 16


def test_spec_example_is_three_days_plus_forensics():
    decision = bod_deadline(
        in_kev=True,
        publicly_exposed=True,
        automatable=False,
        technical_impact="total",
        first_observed=date(2026, 10, 2),
        kev_date_added=date(2026, 10, 14),
        kev_catalog_due=date(2026, 10, 17),
    )
    assert decision.outcome == OUTCOME_3F
    assert decision.forensics_required is True
    assert decision.days == 3
    assert decision.decision_path == (
        "KEV=Yes → Exposed=Yes → Automatable=No → Total impact → "
        "3 days + forensic triage"
    )
    # Earlier of first seen (Oct 2) and KEV addition (Oct 14).
    assert decision.clock_start == date(2026, 10, 2)
    assert decision.deadline == date(2026, 10, 5)
    assert "first seen" in decision.clock_reason


def test_clock_uses_kev_addition_when_it_is_earlier():
    decision = bod_deadline(
        in_kev=True,
        publicly_exposed=False,
        automatable=False,
        technical_impact="partial",
        first_observed=date(2026, 10, 16),
        kev_date_added=date(2026, 10, 10),
    )
    assert decision.outcome == OUTCOME_14
    assert decision.clock_start == date(2026, 10, 10)
    assert decision.deadline == date(2026, 10, 24)
    assert "added the CVE to KEV" in decision.clock_reason


def test_non_kev_clock_is_first_seen_only():
    decision = bod_deadline(
        in_kev=False,
        publicly_exposed=False,
        automatable=False,
        technical_impact="partial",
        first_observed=date(2026, 9, 1),
        kev_date_added=date(2026, 10, 1),
    )
    assert decision.outcome == OUTCOME_FSU
    assert decision.days is None
    assert decision.deadline is None
    assert decision.clock_start == date(2026, 9, 1)


def test_missing_ssvc_uses_cisa_fallback_and_marks_it():
    decision = bod_deadline(
        in_kev=False,
        publicly_exposed=True,
        automatable=None,
        technical_impact=None,
        first_observed=date(2026, 10, 1),
    )
    # Assumed Automatable=No, Technical Impact=Total, exposed, not KEV → 14 days.
    assert decision.automatable is False
    assert decision.technical_impact == "total"
    assert decision.automatable_assumed is True
    assert decision.technical_impact_assumed is True
    assert decision.outcome == OUTCOME_14
    assert "(assumed)" in decision.decision_path
    assert decision.assumptions


def test_due_date_matches_cisa_plus_three_pattern():
    added = date(2026, 10, 16)
    decision = bod_deadline(
        in_kev=True,
        publicly_exposed=True,
        automatable=True,
        technical_impact="total",
        first_observed=added,
        kev_date_added=added,
    )
    assert decision.deadline == added + timedelta(days=3)
    assert days_remaining(decision.deadline, added) == 3
    assert days_remaining(decision.deadline, decision.deadline) == 0
    assert days_remaining(decision.deadline, decision.deadline + timedelta(days=1)) == -1


def test_unknown_impact_is_rejected_after_normalization():
    with pytest.raises(ValueError):
        lookup_outcome(True, True, True, "severe")
