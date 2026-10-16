"""KEV + EPSS + CVSS priority score."""

import pytest

from kev_radar.scoring import (
    CVSS_WEIGHT,
    EPSS_WEIGHT,
    EXPOSURE_WEIGHT,
    KEV_WEIGHT,
    RANSOMWARE_WEIGHT,
    band_for,
    priority_score,
)


def test_weights_sum_to_100():
    assert KEV_WEIGHT + RANSOMWARE_WEIGHT + EPSS_WEIGHT + CVSS_WEIGHT + EXPOSURE_WEIGHT == 100


def test_full_signals_score_100():
    scored = priority_score(
        in_kev=True,
        ransomware=True,
        epss=1.0,
        cvss=10.0,
        publicly_exposed=True,
    )
    assert scored.value == 100.0
    assert scored.band == "Critical"
    assert "35.0 KEV" in scored.summary
    assert "10.0 Ransomware" in scored.summary
    assert "25.0 EPSS" in scored.summary
    assert "20.0 CVSS" in scored.summary
    assert "10.0 Exposure" in scored.summary


def test_partial_epss_and_cvss():
    scored = priority_score(
        in_kev=True,
        ransomware=False,
        epss=0.5,
        cvss=8.0,
        publicly_exposed=False,
    )
    # 35 + 0 + 12.5 + 16 + 0
    assert scored.value == 63.5
    assert scored.band == "High"


def test_missing_epss_and_cvss_contribute_zero():
    scored = priority_score(
        in_kev=False,
        ransomware=False,
        epss=None,
        cvss=None,
        publicly_exposed=True,
    )
    assert scored.value == 10.0
    assert scored.band == "Low"
    details = " ".join(component.detail for component in scored.components)
    assert "EPSS score unavailable" in details
    assert "CVSS base score unavailable" in details


def test_scores_are_clamped():
    scored = priority_score(
        in_kev=False,
        ransomware=False,
        epss=1.4,
        cvss=14,
        publicly_exposed=False,
    )
    assert scored.value == round(EPSS_WEIGHT + CVSS_WEIGHT, 1)


@pytest.mark.parametrize(
    ("score", "band"),
    [(70, "Critical"), (69.9, "High"), (40, "High"), (39.9, "Medium"), (15, "Medium"), (14.9, "Low"), (0, "Low")],
)
def test_bands(score, band):
    assert band_for(score) == band
