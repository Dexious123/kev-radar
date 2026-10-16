"""BOD 26-04 remediation deadlines.

The sixteen outcomes are CERT/CC SSVC model ``cisa:BOD2604:1.0.0``
(https://certcc.github.io/SSVC/howto/cisa_response/). CISA's directive points
at those Vulnrichment definitions. The clock-start sentence, the forensic
triage requirement, and the fix-on-upgrade definition are quoted from the
directive itself:

https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk

Missing-data fallbacks, the exposure order, and the six forensic-triage steps
come from the implementation guidance (issued June 10, 2026, updated August
25, 2026):

https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta

DIRECTIVE_URL = (
    "https://www.cisa.gov/news-events/directives/"
    "bod-26-04-prioritizing-security-updates-based-risk"
)
GUIDANCE_URL = (
    "https://www.cisa.gov/news-events/directives/"
    "bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk"
)
CERT_TABLE_URL = "https://certcc.github.io/SSVC/howto/cisa_response/"
VULNRICHMENT_REPO = "https://github.com/cisagov/vulnrichment"

# Directive, required action 2.d: "& forensic triage" means remediate within
# three days and assess whether the asset is compromised. The hour ranges
# below are the implementation guidance's recommended practice. The directive
# requires an adequate triage, not those hour targets. A KEV entry's own
# notes override this baseline when CISA publishes them.
FORENSIC_TRIAGE_STEPS: tuple[tuple[str, str], ...] = (
    (
        "1. Scoping",
        "Identify whether the CVE meets the under-three-day threshold and needs "
        "triage, then bound the systems in scope. Recommended window: the first "
        "two hours after the KEV addition.",
    ),
    (
        "2. Preserve and collect evidence",
        "Take volatile data first, then less volatile artifacts, and keep a "
        "collection log. Do not patch before evidence is collected when you can "
        "avoid it. Recommended window: 2–24 hours.",
    ),
    (
        "3. Critical patching and stabilization",
        "Apply the critical patch only after the evidence needed for triage is "
        "in hand, and stabilize the business process if the patch disrupts it. "
        "Recommended window: 2–24 hours.",
    ),
    (
        "4. Contain and control",
        "Isolate in-scope systems after initial collection, coordinated so the "
        "containment does not tip off the actor or destroy evidence. "
        "Recommended window: 6–24 hours.",
    ),
    (
        "5. Triage analysis",
        "Decide whether unauthorized access, persistence, lateral movement, or "
        "exfiltration occurred, and document the indicators. Recommended window: "
        "24–48 hours.",
    ),
    (
        "6. Escalation decision",
        "Write the triage report and either close with heightened monitoring or "
        "escalate a confirmed or suspected compromise to CISA. Recommended "
        "window: 48–72 hours.",
    ),
)

FORENSIC_TRIAGE_NOTE = (
    "BOD 26-04 says “& forensic triage” means the agency remediates or mitigates "
    "within three days and carries out a forensic triage to assess whether the "
    "system is compromised. An adequate triage follows the implementation "
    "guidance. The hour ranges on those six steps are recommended best practice; "
    "the directive does not require that specific timeline. If the KEV catalog "
    "entry has its own triage notes, follow those."
)

OUTCOME_FSU = "fix_on_upgrade"
OUTCOME_60 = "60_days"
OUTCOME_14 = "14_days"
OUTCOME_3 = "3_days"
OUTCOME_3F = "3_days_forensics"

OUTCOME_META: dict[str, dict] = {
    OUTCOME_FSU: {
        "label": "Fix on system upgrade",
        "days": None,
        "forensics": False,
        "key": "FSU",
    },
    OUTCOME_60: {"label": "60 days", "days": 60, "forensics": False, "key": "60D"},
    OUTCOME_14: {"label": "14 days", "days": 14, "forensics": False, "key": "14D"},
    OUTCOME_3: {"label": "3 days", "days": 3, "forensics": False, "key": "3D"},
    OUTCOME_3F: {
        "label": "3 days + forensic triage",
        "days": 3,
        "forensics": True,
        "key": "3DF",
    },
}

# (in_kev, publicly_exposed, automatable, technical_impact) -> outcome
# technical_impact is "partial" or "total". Bools are Yes=True.
DECISION_TABLE: dict[tuple[bool, bool, bool, str], str] = {
    (False, False, False, "partial"): OUTCOME_FSU,
    (True, False, False, "partial"): OUTCOME_14,
    (False, True, False, "partial"): OUTCOME_60,
    (False, False, True, "partial"): OUTCOME_60,
    (False, False, False, "total"): OUTCOME_FSU,
    (True, True, False, "partial"): OUTCOME_14,
    (True, False, True, "partial"): OUTCOME_14,
    (False, True, True, "partial"): OUTCOME_14,
    (True, False, False, "total"): OUTCOME_14,
    (False, True, False, "total"): OUTCOME_14,
    (False, False, True, "total"): OUTCOME_60,
    (True, True, True, "partial"): OUTCOME_3,
    (True, True, False, "total"): OUTCOME_3F,
    (True, False, True, "total"): OUTCOME_3F,
    (False, True, True, "total"): OUTCOME_3,
    (True, True, True, "total"): OUTCOME_3F,
}


def normalize_impact(value: str | None) -> str | None:
    """Return ``partial`` or ``total``, or None when the field is unusable."""
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"", "unknown", "none", "nan", "null"}:
        return None
    if text in {"partial", "p", "limited"}:
        return "partial"
    if text in {"total", "t", "high"}:
        return "total"
    return None


def normalize_yes_no(value: str | bool | None) -> bool | None:
    """Return a bool, or None when the field is missing or unrecognized."""
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"", "unknown", "nan", "null", "none"}:
        return None
    if text in {"yes", "y", "true", "1"}:
        return True
    if text in {"no", "n", "false", "0"}:
        return False
    return None


def lookup_outcome(
    in_kev: bool,
    publicly_exposed: bool,
    automatable: bool,
    technical_impact: str,
) -> str:
    """Return the outcome key for one complete decision path."""
    impact = normalize_impact(technical_impact)
    if impact is None:
        raise ValueError(
            "technical_impact must be 'partial' or 'total' once fallbacks are applied"
        )
    key = (bool(in_kev), bool(publicly_exposed), bool(automatable), impact)
    try:
        return DECISION_TABLE[key]
    except KeyError as exc:
        raise ValueError(f"No BOD 26-04 row for {key}") from exc


@dataclass(frozen=True)
class DeadlineDecision:
    in_kev: bool
    publicly_exposed: bool
    automatable: bool
    technical_impact: str
    automatable_assumed: bool
    technical_impact_assumed: bool
    outcome: str
    outcome_key: str
    outcome_label: str
    days: int | None
    forensics_required: bool
    decision_path: str
    assumptions: tuple[str, ...]
    clock_start: date | None
    clock_reason: str
    deadline: date | None
    kev_catalog_due: date | None

    @property
    def assumed(self) -> bool:
        return self.automatable_assumed or self.technical_impact_assumed


def _apply_fallbacks(
    automatable: bool | None,
    technical_impact: str | None,
) -> tuple[bool, str, bool, bool, tuple[str, ...]]:
    """CISA FAQ fallback: missing Automatable → no, missing Technical Impact → total.

    The implementation guidance states this rule for CVEs that are not in the
    KEV catalog. The same stand-in is used when a KEV entry has no Vulnrichment
    row in the local snapshot, and the decision is marked assumed either way.
    """
    notes: list[str] = []
    auto_assumed = automatable is None
    impact_assumed = technical_impact is None
    if auto_assumed:
        automatable = False
        notes.append(
            "Automatable was missing from Vulnrichment. CISA's BOD 26-04 "
            "implementation guidance treats a missing value as No until "
            "enrichment is published."
        )
    if impact_assumed:
        technical_impact = "total"
        notes.append(
            "Technical Impact was missing from Vulnrichment. CISA's BOD 26-04 "
            "implementation guidance treats a missing value as Total until "
            "enrichment is published."
        )
    return bool(automatable), str(technical_impact), auto_assumed, impact_assumed, tuple(notes)


def _yn(flag: bool) -> str:
    return "Yes" if flag else "No"


def decision_path(
    in_kev: bool,
    publicly_exposed: bool,
    automatable: bool,
    technical_impact: str,
    outcome_label: str,
    automatable_assumed: bool = False,
    technical_impact_assumed: bool = False,
    exposure_assumed: bool = False,
) -> str:
    impact_word = "Total" if technical_impact == "total" else "Partial"
    auto = f"Automatable={_yn(automatable)}"
    if automatable_assumed:
        auto += " (assumed)"
    exposed = f"Exposed={_yn(publicly_exposed)}"
    if exposure_assumed:
        exposed += " (assumed)"
    impact = f"{impact_word} impact"
    if technical_impact_assumed:
        impact += " (assumed)"
    return (
        f"KEV={_yn(in_kev)} → {exposed} → {auto} → "
        f"{impact} → {outcome_label}"
    )


def resolve_clock(
    in_kev: bool,
    first_observed: date | None,
    kev_date_added: date | None,
) -> tuple[date | None, str]:
    """Clock start is the earlier of KEV addition and asset enumeration.

    BOD 26-04 required action on Table 1: the timelines begin when either
    (1) CISA adds the vulnerability to the KEV catalog, or (2) pursuant to
    BOD 23-01, the agency enumerates or identifies it on an asset and updates
    the CDM dashboard. Whichever event happens first starts the clock.
    Non-KEV findings have only the enumeration date. In this app, first seen
    stands in for that enumeration.
    """
    candidates: list[tuple[date, str]] = []
    if first_observed is not None:
        candidates.append((first_observed, "the finding was first seen on this asset"))
    if in_kev and kev_date_added is not None:
        candidates.append((kev_date_added, "CISA added the CVE to the KEV catalog"))
    if not candidates:
        return None, "No first-seen date and no KEV addition date, so no deadline can be set."
    start, _ = min(candidates, key=lambda item: item[0])
    if len(candidates) == 1:
        reason = f"Clock started {start.isoformat()} when {candidates[0][1]}."
        if in_kev:
            reason += (
                " BOD 26-04 starts the remediation clock on the earlier of KEV "
                "addition and asset enumeration."
            )
        return start, reason
    observed, added = first_observed, kev_date_added
    assert observed is not None and added is not None
    if observed == added:
        reason = (
            f"Clock started {start.isoformat()}, the day the finding was first "
            "seen and the day CISA added it to KEV."
        )
    elif start == observed:
        reason = (
            f"Clock started {start.isoformat()}, when the finding was first seen, "
            f"which is earlier than the KEV addition on {added.isoformat()}."
        )
    else:
        reason = (
            f"Clock started {start.isoformat()}, when CISA added the CVE to KEV, "
            f"which is earlier than the first scan on {observed.isoformat()}."
        )
    reason += (
        " BOD 26-04 starts the remediation clock on the earlier of KEV addition "
        "and asset enumeration."
    )
    return start, reason


def bod_deadline(
    *,
    in_kev: bool,
    publicly_exposed: bool,
    automatable: bool | None,
    technical_impact: str | None,
    first_observed: date | None = None,
    kev_date_added: date | None = None,
    kev_catalog_due: date | None = None,
    exposure_assumed: bool = False,
) -> DeadlineDecision:
    """Score one finding and explain the deadline."""
    impact = normalize_impact(technical_impact)
    auto = automatable if isinstance(automatable, bool) else normalize_yes_no(automatable)
    auto, impact, auto_assumed, impact_assumed, assumptions = _apply_fallbacks(auto, impact)
    outcome = lookup_outcome(in_kev, publicly_exposed, auto, impact)
    meta = OUTCOME_META[outcome]
    path = decision_path(
        in_kev,
        publicly_exposed,
        auto,
        impact,
        meta["label"],
        automatable_assumed=auto_assumed,
        technical_impact_assumed=impact_assumed,
        exposure_assumed=exposure_assumed,
    )
    clock_start, clock_reason = resolve_clock(in_kev, first_observed, kev_date_added)
    days = meta["days"]
    deadline = None
    if clock_start is not None and days is not None:
        deadline = clock_start + timedelta(days=days)
    return DeadlineDecision(
        in_kev=bool(in_kev),
        publicly_exposed=bool(publicly_exposed),
        automatable=auto,
        technical_impact=impact,
        automatable_assumed=auto_assumed,
        technical_impact_assumed=impact_assumed,
        outcome=outcome,
        outcome_key=meta["key"],
        outcome_label=meta["label"],
        days=days,
        forensics_required=bool(meta["forensics"]),
        decision_path=path,
        assumptions=assumptions,
        clock_start=clock_start,
        clock_reason=clock_reason,
        deadline=deadline,
        kev_catalog_due=kev_catalog_due,
    )


def days_remaining(deadline: date | None, as_of: date) -> int | None:
    """Days until ``deadline``. Negative means the deadline has passed.

    The due date itself still counts as on time (zero days left).
    """
    if deadline is None:
        return None
    return (deadline - as_of).days
