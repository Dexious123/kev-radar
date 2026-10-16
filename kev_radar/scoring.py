"""Priority score from KEV, EPSS, CVSS, ransomware use, and exposure.

The score is a weighted sum on a 0–100 scale so a row can be sorted and
explained without hiding the inputs:

- 35 points if the CVE is in CISA KEV
- 10 points if KEV records known ransomware campaign use
- up to 25 points from the FIRST EPSS probability (EPSS × 25)
- up to 20 points from CVSS base (CVSS / 10 × 20)
- 10 points if the asset is publicly exposed

Missing EPSS or CVSS contributes zero and is called out in the breakdown.
Bands are labels for the queue, not a second scoring system: Critical ≥ 70,
High ≥ 40, Medium ≥ 15, otherwise Low.
"""

from __future__ import annotations

from dataclasses import dataclass

KEV_WEIGHT = 35.0
RANSOMWARE_WEIGHT = 10.0
EPSS_WEIGHT = 25.0
CVSS_WEIGHT = 20.0
EXPOSURE_WEIGHT = 10.0


def band_for(score: float) -> str:
    if score >= 70:
        return "Critical"
    if score >= 40:
        return "High"
    if score >= 15:
        return "Medium"
    return "Low"


@dataclass(frozen=True)
class ScoreComponent:
    name: str
    points: float
    detail: str


@dataclass(frozen=True)
class PriorityScore:
    value: float
    band: str
    components: tuple[ScoreComponent, ...]
    summary: str


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def priority_score(
    *,
    in_kev: bool,
    ransomware: bool,
    epss: float | None,
    cvss: float | None,
    publicly_exposed: bool,
) -> PriorityScore:
    """Combine the public signals into one explainable score."""
    components: list[ScoreComponent] = []

    if in_kev:
        components.append(ScoreComponent("KEV", KEV_WEIGHT, "Listed in the CISA KEV catalog"))
    else:
        components.append(ScoreComponent("KEV", 0.0, "Not in the CISA KEV catalog"))

    if ransomware:
        components.append(
            ScoreComponent(
                "Ransomware",
                RANSOMWARE_WEIGHT,
                "KEV knownRansomwareCampaignUse is Known",
            )
        )
    else:
        components.append(
            ScoreComponent("Ransomware", 0.0, "No known ransomware campaign use on the KEV entry")
        )

    if epss is None:
        components.append(
            ScoreComponent("EPSS", 0.0, "FIRST EPSS score unavailable; counted as 0")
        )
        epss_points = 0.0
    else:
        probability = _clamp(float(epss), 0.0, 1.0)
        epss_points = EPSS_WEIGHT * probability
        components.append(
            ScoreComponent(
                "EPSS",
                epss_points,
                f"FIRST EPSS {probability:.1%} × {EPSS_WEIGHT:.0f}",
            )
        )

    if cvss is None:
        components.append(ScoreComponent("CVSS", 0.0, "CVSS base score unavailable; counted as 0"))
        cvss_points = 0.0
    else:
        base = _clamp(float(cvss), 0.0, 10.0)
        cvss_points = CVSS_WEIGHT * (base / 10.0)
        components.append(
            ScoreComponent(
                "CVSS",
                cvss_points,
                f"CVSS {base:.1f} / 10 × {CVSS_WEIGHT:.0f}",
            )
        )

    if publicly_exposed:
        components.append(
            ScoreComponent("Exposure", EXPOSURE_WEIGHT, "Asset is publicly exposed")
        )
    else:
        components.append(ScoreComponent("Exposure", 0.0, "Asset is not publicly exposed"))

    total = round(sum(component.points for component in components), 1)
    parts = [
        f"{component.points:.1f} {component.name}"
        for component in components
        if component.points
    ]
    summary = " + ".join(parts) if parts else "No priority points from KEV, EPSS, CVSS, or exposure"
    return PriorityScore(
        value=total,
        band=band_for(total),
        components=tuple(components),
        summary=summary,
    )
