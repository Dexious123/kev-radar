"""Classic CISA SSVC table spot checks against the published 36-row guide."""

import pytest

from kev_radar.ssvc import cisa_ssvc


@pytest.mark.parametrize(
    ("exploitation", "automatable", "impact", "mission", "decision"),
    [
        ("none", False, "partial", "low", "Track"),
        ("none", False, "total", "high", "Track*"),
        ("poc", False, "total", "medium", "Track*"),
        ("poc", False, "total", "high", "Attend"),
        ("active", False, "total", "medium", "Attend"),
        ("active", False, "total", "high", "Act"),
        ("active", True, "total", "medium", "Act"),
        ("active", True, "partial", "low", "Attend"),
    ],
)
def test_published_rows(exploitation, automatable, impact, mission, decision):
    result = cisa_ssvc(
        exploitation=exploitation,
        automatable=automatable,
        technical_impact=impact,
        mission=mission,
        in_kev=False,
    )
    assert result.decision == decision
    assert result.exploitation_assumed is False


def test_kev_without_exploitation_is_treated_as_active():
    result = cisa_ssvc(
        exploitation=None,
        automatable=True,
        technical_impact="total",
        mission="medium",
        in_kev=True,
    )
    assert result.exploitation == "active"
    assert result.exploitation_assumed is True
    assert result.decision == "Act"


def test_mission_must_be_a_known_level():
    with pytest.raises(ValueError):
        cisa_ssvc(
            exploitation="none",
            automatable=False,
            technical_impact="partial",
            mission="essential",
        )
