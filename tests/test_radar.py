"""The deadline radar places real findings; these pin where and how."""

import re
from datetime import date, timedelta

import pandas as pd

from kev_radar.radar import BANDS, MAX_DOTS, SWEEP_SECONDS, band_for, build_radar, radial_fraction

AS_OF = date(2026, 10, 17)


def _row(cve, days, *, unit="Payments", state="open", paused=False, score=50.0, host="h.lab.invalid"):
    return {
        "cve": cve,
        "host_name": host,
        "owner": "Priya Shah",
        "business_unit": unit,
        "state": state,
        "sla_paused": paused,
        "deadline": AS_OF + timedelta(days=days) if days is not None else None,
        "score": score,
    }


def test_band_boundaries_follow_the_deadline_tiers():
    assert [band_for(d) for d in (-1, 0, 7, 8, 30, 31)] == ["past", "near", "near", "soon", "soon", "far"]


def test_less_time_left_sits_closer_to_the_center():
    edges = {key: edge for key, _, edge in BANDS}
    samples = {"past": [-900, -30, -1], "near": [0, 3, 7], "soon": [8, 20, 30], "far": [31, 90, 400]}
    previous_edge = 0.0
    for band, days_list in samples.items():
        for days in days_list:
            fraction = radial_fraction(days, f"k{days}")
            assert previous_edge < fraction < edges[band], (band, days, fraction)
        previous_edge = edges[band]
    assert radial_fraction(-900, "same") < radial_fraction(-2, "same")


def test_only_open_unpaused_findings_with_a_deadline_are_plotted():
    frame = pd.DataFrame(
        [
            _row("CVE-2026-0001", -3),
            _row("CVE-2026-0002", 5),
            _row("CVE-2026-0003", 40),
            _row("CVE-2026-0004", -9, state="fixed"),
            _row("CVE-2026-0005", -9, paused=True),
            _row("CVE-2026-0006", None),
        ]
    )
    radar = build_radar(frame, AS_OF)
    assert radar.plotted == 3
    assert radar.counts == {"past": 1, "near": 1, "soon": 0, "far": 1}
    assert radar.svg.count('<circle class="dot') == 3
    assert "CVE-2026-0004" not in radar.svg and "CVE-2026-0005" not in radar.svg


def test_text_from_an_upload_is_escaped():
    frame = pd.DataFrame([_row("CVE-2026-0001", -3, unit='<script>alert("x")</script>', host="<b>h</b>")])
    svg = build_radar(frame, AS_OF).svg
    assert "<script>" not in svg and "<b>h</b>" not in svg
    assert "&lt;script&gt;" in svg


def test_positions_are_stable_and_each_dot_flashes_when_the_sweep_passes():
    frame = pd.DataFrame([_row(f"CVE-2026-{n:04d}", n - 20, unit=u) for n, u in enumerate(["A", "B", "C"] * 5)])
    first, second = build_radar(frame, AS_OF).svg, build_radar(frame, AS_OF).svg
    assert first == second
    delays = [float(d) for d in re.findall(r"animation-delay:(-?\d+\.\d+)s", first)]
    assert delays and all(-SWEEP_SECONDS <= d <= 0 for d in delays)


def test_a_large_estate_keeps_the_highest_scores_up_to_the_cap():
    rows = [_row(f"CVE-2026-{n:05d}", 10, score=n % 100, host=f"h{n}.lab.invalid") for n in range(MAX_DOTS + 50)]
    radar = build_radar(pd.DataFrame(rows), AS_OF)
    assert radar.plotted == MAX_DOTS
    assert radar.counts["soon"] == MAX_DOTS + 50


def test_more_than_eight_units_fold_into_other():
    rows = [_row(f"CVE-2026-{n:04d}", 3, unit=f"Unit {n}") for n in range(11)]
    svg = build_radar(pd.DataFrame(rows), AS_OF).svg
    assert svg.count('class="slice-label"') == 8
    assert ">Other<" in svg


def test_an_empty_estate_still_draws_the_scope():
    radar = build_radar(pd.DataFrame(), AS_OF)
    assert radar.plotted == 0 and radar.svg.startswith("<svg") and "Past due" in radar.svg
