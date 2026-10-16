"""Join findings to KEV, EPSS, and Vulnrichment, then score and deadline them."""

from __future__ import annotations

from datetime import date

import pandas as pd

from kev_radar.bod import bod_deadline, normalize_impact, normalize_yes_no
from kev_radar.exposure import finalize_exposure
from kev_radar.kevdiff import ransomware_known, triage_status
from kev_radar.metrics import days_left, sla_status
from kev_radar.scoring import priority_score
from kev_radar.ssvc import cisa_ssvc

PRIORITIZED_COLUMNS = [
    "host_key",
    "host_name",
    "asset_name",
    "ip",
    "operating_system",
    "system_type",
    "owner",
    "business_unit",
    "exposed",
    "exposure_reason",
    "exposure_basis",
    "exposure_assumed",
    "cve",
    "plugin_ids",
    "plugin_name",
    "severity",
    "state",
    "first_observed",
    "last_seen",
    "last_fixed",
    "raw_row_count",
    "output",
    "solution",
    "port",
    "protocol",
    "in_kev",
    "ransomware",
    "kev_date_added",
    "kev_due_date",
    "kev_vendor",
    "kev_product",
    "vuln_name",
    "required_action",
    "triage",
    "epss",
    "epss_source",
    "cvss",
    "cvss_source",
    "cvss_vector",
    "exploitation",
    "automatable",
    "technical_impact",
    "automatable_assumed",
    "technical_impact_assumed",
    "outcome",
    "outcome_key",
    "outcome_label",
    "forensics_required",
    "decision_path",
    "assumption_notes",
    "clock_start",
    "clock_reason",
    "deadline",
    "days_left",
    "sla_status",
    "score",
    "band",
    "score_summary",
    "ssvc_decision",
    "ssvc_path",
]


def _pydate(value: object) -> date | None:
    if value is None:
        return None
    try:
        if pd.isna(value):
            return None
    except TypeError:
        pass
    if isinstance(value, pd.Timestamp):
        return None if pd.isna(value) else value.date()
    if isinstance(value, date):
        return value
    return None


def _date_from_kev(value: object) -> date | None:
    if value is None or str(value).strip() == "":
        return None
    text = str(value).strip()[:10]
    try:
        year, month, day = (int(part) for part in text.split("-"))
        return date(year, month, day)
    except ValueError:
        return None


def _epss_value(scores: dict, cve: str, scanner_value: object) -> tuple[float | None, str]:
    raw = scores.get(cve)
    if isinstance(raw, dict):
        raw = raw.get("epss")
    if raw is not None:
        try:
            return float(raw), "FIRST EPSS"
        except (TypeError, ValueError):
            pass
    if scanner_value is not None and not (isinstance(scanner_value, float) and pd.isna(scanner_value)):
        try:
            value = float(scanner_value)
        except (TypeError, ValueError):
            value = None
        if value is not None:
            # Scanner exports sometimes store EPSS as a percent.
            if value > 1:
                value = value / 100.0
            return value, "Scanner column"
    return None, "Unavailable"


def _ssvc_fields(record: dict | None) -> dict:
    if not record:
        return {
            "automatable": None,
            "technical_impact": None,
            "exploitation": None,
            "cvss": None,
            "cvss_vector": None,
        }
    return {
        "automatable": normalize_yes_no(record.get("automatable")),
        "technical_impact": normalize_impact(record.get("technical_impact")),
        "exploitation": record.get("exploitation"),
        "cvss": record.get("cvss"),
        "cvss_vector": record.get("cvss_vector"),
    }


def prioritize(
    findings: pd.DataFrame,
    kev_by_id: dict[str, dict],
    epss_scores: dict,
    ssvc_by_id: dict[str, dict],
    as_of: date,
    *,
    mission: str = "medium",
) -> pd.DataFrame:
    """Return one row per finding with deadline, score, and classic SSVC."""
    if findings.empty:
        return pd.DataFrame(columns=PRIORITIZED_COLUMNS)
    rows: list[dict] = []
    for record in findings.to_dict(orient="records"):
        cve = str(record.get("cve") or "").upper()
        record["first_observed"] = _pydate(record.get("first_observed"))
        record["last_seen"] = _pydate(record.get("last_seen"))
        record["last_fixed"] = _pydate(record.get("last_fixed"))
        kev = kev_by_id.get(cve)
        in_kev = kev is not None
        enrichment = _ssvc_fields(ssvc_by_id.get(cve))
        scanner_cvss = record.get("cvss")
        if scanner_cvss is not None and not (isinstance(scanner_cvss, float) and pd.isna(scanner_cvss)):
            cvss = float(scanner_cvss)
            cvss_source = "Scanner"
            cvss_vector = record.get("cvss_vector")
        elif enrichment["cvss"] is not None:
            cvss = float(enrichment["cvss"])
            cvss_source = "Vulnrichment"
            cvss_vector = enrichment["cvss_vector"]
        else:
            cvss = None
            cvss_source = "Unavailable"
            cvss_vector = None
        epss, epss_source = _epss_value(epss_scores, cve, record.get("scanner_epss"))
        kev_added = _date_from_kev(kev.get("dateAdded")) if kev else None
        kev_due = _date_from_kev(kev.get("dueDate")) if kev else None
        product_text = " ".join(
            str(part or "")
            for part in (
                (kev or {}).get("vendorProject"),
                (kev or {}).get("product"),
                (kev or {}).get("vulnerabilityName"),
                record.get("plugin_name"),
            )
        )
        facing = record.get("public_facing_tag")
        if facing is not None and not isinstance(facing, bool):
            try:
                if pd.isna(facing):
                    facing = None
            except TypeError:
                pass
        exposure = finalize_exposure(
            exposed=bool(record.get("exposed")),
            reason=str(record.get("exposure_reason") or ""),
            basis=str(record.get("exposure_basis") or "unresolved"),
            public_facing_tag=facing if isinstance(facing, bool) else None,
            in_kev=in_kev,
            product_text=product_text,
        )
        decision = bod_deadline(
            in_kev=in_kev,
            publicly_exposed=exposure.exposed,
            automatable=enrichment["automatable"],
            technical_impact=enrichment["technical_impact"],
            first_observed=record.get("first_observed"),
            kev_date_added=kev_added,
            kev_catalog_due=kev_due,
            exposure_assumed=exposure.assumed,
        )
        classic = cisa_ssvc(
            exploitation=enrichment["exploitation"],
            automatable=enrichment["automatable"],
            technical_impact=enrichment["technical_impact"],
            mission=mission,
            in_kev=in_kev,
        )
        ransomware = ransomware_known(kev) if kev else False
        scored = priority_score(
            in_kev=in_kev,
            ransomware=ransomware,
            epss=epss,
            cvss=cvss,
            publicly_exposed=exposure.exposed,
        )
        name = record.get("plugin_name") or cve
        if kev and kev.get("vulnerabilityName"):
            name = kev["vulnerabilityName"]
        rows.append(
            {
                **{key: record.get(key) for key in (
                    "host_key",
                    "host_name",
                    "asset_name",
                    "ip",
                    "operating_system",
                    "system_type",
                    "owner",
                    "business_unit",
                    "exposed",
                    "exposure_reason",
                    "exposure_basis",
                    "plugin_ids",
                    "severity",
                    "state",
                    "first_observed",
                    "last_seen",
                    "last_fixed",
                    "raw_row_count",
                    "output",
                    "solution",
                    "port",
                    "protocol",
                )},
                "exposed": exposure.exposed,
                "exposure_reason": exposure.reason,
                "exposure_basis": exposure.basis,
                "exposure_assumed": exposure.assumed,
                "cve": cve,
                "plugin_name": record.get("plugin_name"),
                "in_kev": in_kev,
                "ransomware": ransomware,
                "kev_date_added": kev_added,
                "kev_due_date": kev_due,
                "kev_vendor": (kev or {}).get("vendorProject"),
                "kev_product": (kev or {}).get("product"),
                "vuln_name": name,
                "required_action": (kev or {}).get("requiredAction"),
                "triage": triage_status(kev) if kev else "not_in_feed",
                "epss": epss,
                "epss_source": epss_source,
                "cvss": cvss,
                "cvss_source": cvss_source,
                "cvss_vector": cvss_vector,
                "exploitation": classic.exploitation,
                "automatable": decision.automatable,
                "technical_impact": decision.technical_impact,
                "automatable_assumed": decision.automatable_assumed,
                "technical_impact_assumed": decision.technical_impact_assumed,
                "outcome": decision.outcome,
                "outcome_key": decision.outcome_key,
                "outcome_label": decision.outcome_label,
                "forensics_required": decision.forensics_required,
                "decision_path": decision.decision_path,
                "assumption_notes": " ".join(
                    (*decision.assumptions, exposure.reason) if exposure.assumed else decision.assumptions
                ),
                "clock_start": decision.clock_start,
                "clock_reason": decision.clock_reason,
                "deadline": decision.deadline,
                "days_left": days_left(decision.deadline, as_of, decision.outcome),
                "sla_status": sla_status(
                    state=record.get("state"),
                    outcome=decision.outcome,
                    deadline=decision.deadline,
                    last_fixed=record.get("last_fixed"),
                    as_of=as_of,
                ),
                "score": scored.value,
                "band": scored.band,
                "score_summary": scored.summary,
                "ssvc_decision": classic.decision,
                "ssvc_path": classic.decision_path,
            }
        )
    frame = pd.DataFrame(rows, columns=PRIORITIZED_COLUMNS)
    return frame.sort_values(
        ["score", "days_left"],
        ascending=[False, True],
        na_position="last",
    ).reset_index(drop=True)
