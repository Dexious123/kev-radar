"""Older CISA SSVC decisions: Track, Track*, Attend, Act.

Table source: CISA Stakeholder-Specific Vulnerability Categorization Guide,
the 36-row decision table (Exploitation × Automatable × Technical Impact ×
Mission & Well-being). Vulnrichment publishes the first three points.
Mission & well-being is an organizational input, so the caller supplies it.
"""

from __future__ import annotations

from dataclasses import dataclass

from kev_radar.bod import normalize_impact, normalize_yes_no

MISSION_LEVELS = ("low", "medium", "high")

# (exploitation, automatable, technical_impact, mission) -> decision
CISA_SSVC_TABLE: dict[tuple[str, bool, str, str], str] = {
    ("none", False, "partial", "low"): "Track",
    ("none", False, "partial", "medium"): "Track",
    ("none", False, "partial", "high"): "Track",
    ("none", False, "total", "low"): "Track",
    ("none", False, "total", "medium"): "Track",
    ("none", False, "total", "high"): "Track*",
    ("none", True, "partial", "low"): "Track",
    ("none", True, "partial", "medium"): "Track",
    ("none", True, "partial", "high"): "Attend",
    ("none", True, "total", "low"): "Track",
    ("none", True, "total", "medium"): "Track",
    ("none", True, "total", "high"): "Attend",
    ("poc", False, "partial", "low"): "Track",
    ("poc", False, "partial", "medium"): "Track",
    ("poc", False, "partial", "high"): "Track*",
    ("poc", False, "total", "low"): "Track",
    ("poc", False, "total", "medium"): "Track*",
    ("poc", False, "total", "high"): "Attend",
    ("poc", True, "partial", "low"): "Track",
    ("poc", True, "partial", "medium"): "Track",
    ("poc", True, "partial", "high"): "Attend",
    ("poc", True, "total", "low"): "Track",
    ("poc", True, "total", "medium"): "Track*",
    ("poc", True, "total", "high"): "Attend",
    ("active", False, "partial", "low"): "Track",
    ("active", False, "partial", "medium"): "Track",
    ("active", False, "partial", "high"): "Attend",
    ("active", False, "total", "low"): "Track",
    ("active", False, "total", "medium"): "Attend",
    ("active", False, "total", "high"): "Act",
    ("active", True, "partial", "low"): "Attend",
    ("active", True, "partial", "medium"): "Attend",
    ("active", True, "partial", "high"): "Act",
    ("active", True, "total", "low"): "Attend",
    ("active", True, "total", "medium"): "Act",
    ("active", True, "total", "high"): "Act",
}


def normalize_exploitation(value: str | None, *, in_kev: bool = False) -> tuple[str, bool]:
    """Return ``(none|poc|active, assumed)``.

    A KEV listing is evidence of active exploitation. When Vulnrichment has
    no Exploitation value, KEV findings are treated as active and others as none.
    """
    if value is not None:
        text = str(value).strip().lower().replace("_", " ").replace("-", " ")
        if text in {"active", "active exploitation", "exploited"}:
            return "active", False
        if text in {"poc", "proof of concept", "public poc", "pocexists"}:
            return "poc", False
        if text in {"none", "no", "unproven"}:
            return "none", False
    if in_kev:
        return "active", True
    return "none", True


@dataclass(frozen=True)
class SsvcDecision:
    exploitation: str
    exploitation_assumed: bool
    automatable: bool
    automatable_assumed: bool
    technical_impact: str
    technical_impact_assumed: bool
    mission: str
    decision: str
    decision_path: str


def cisa_ssvc(
    *,
    exploitation: str | None,
    automatable: bool | None,
    technical_impact: str | None,
    mission: str = "medium",
    in_kev: bool = False,
) -> SsvcDecision:
    """Map Vulnrichment points plus a mission level to Track / Track* / Attend / Act."""
    mission_key = str(mission).strip().lower()
    if mission_key not in MISSION_LEVELS:
        raise ValueError("mission must be low, medium, or high")
    exploit, exploit_assumed = normalize_exploitation(exploitation, in_kev=in_kev)
    impact = normalize_impact(technical_impact)
    impact_assumed = impact is None
    if impact_assumed:
        impact = "total"
    auto = automatable if isinstance(automatable, bool) else normalize_yes_no(automatable)
    auto_assumed = auto is None
    if auto_assumed:
        auto = False
    decision = CISA_SSVC_TABLE[(exploit, bool(auto), impact, mission_key)]
    impact_word = "Total" if impact == "total" else "Partial"
    exploit_label = {"none": "none", "poc": "PoC", "active": "active"}[exploit]
    if exploit_assumed:
        exploit_label += " (assumed)"
    auto_label = "Yes" if auto else "No"
    if auto_assumed:
        auto_label += " (assumed)"
    impact_label = f"{impact_word} impact"
    if impact_assumed:
        impact_label += " (assumed)"
    path = (
        f"Exploitation={exploit_label} → Automatable={auto_label} → "
        f"{impact_label} → Mission & well-being={mission_key} → {decision}"
    )
    return SsvcDecision(
        exploitation=exploit,
        exploitation_assumed=exploit_assumed,
        automatable=bool(auto),
        automatable_assumed=auto_assumed,
        technical_impact=impact,
        technical_impact_assumed=impact_assumed,
        mission=mission_key,
        decision=decision,
        decision_path=path,
    )
