"""BOD 26-04 exposure order, including the generally-public-facing step."""

from datetime import date

import pandas as pd

from kev_radar.bod import DIRECTIVE_URL, FORENSIC_TRIAGE_STEPS, GUIDANCE_URL, bod_deadline
from kev_radar.exposure import finalize_exposure, match_public_facing
from kev_radar.parse import infer_exposure
from kev_radar.prioritize import prioritize


def test_directive_urls_and_forensic_steps():
    assert "bod-26-04-prioritizing-security-updates-based-risk" in DIRECTIVE_URL
    assert "implementation-guidance" in GUIDANCE_URL
    assert len(FORENSIC_TRIAGE_STEPS) == 6
    assert FORENSIC_TRIAGE_STEPS[0][0].startswith("1.")


def test_clock_reason_cites_the_directive_rule():
    decision = bod_deadline(
        in_kev=True,
        publicly_exposed=False,
        automatable=False,
        technical_impact="partial",
        first_observed=date(2026, 10, 16),
        kev_date_added=date(2026, 10, 10),
    )
    assert "earlier of KEV addition" in decision.clock_reason
    assert decision.clock_start == date(2026, 10, 10)


def test_explicit_tag_still_wins():
    call = infer_exposure(False, "8.8.8.8", "network")
    assert call.exposed is False
    assert call.basis == "tag"
    result = finalize_exposure(
        exposed=call.exposed,
        reason=call.reason,
        basis=call.basis,
        public_facing_tag=None,
        in_kev=True,
        product_text="Cisco ASA",
    )
    assert result.exposed is False
    assert result.assumed is False


def test_public_address_and_network_type_bases():
    assert infer_exposure(None, "8.8.8.8", "server").basis == "public_address"
    assert infer_exposure(None, "10.0.0.5", "network").basis == "asset_type"
    assert infer_exposure(None, "10.0.0.5", "server").basis == "unresolved"


def test_step_three_is_kev_only_and_labeled_assumed():
    unresolved = infer_exposure(None, "10.1.1.8", "server")
    kev = finalize_exposure(
        exposed=unresolved.exposed,
        reason=unresolved.reason,
        basis=unresolved.basis,
        public_facing_tag=None,
        in_kev=True,
        product_text="Cisco ASA Software",
    )
    assert kev.exposed is True
    assert kev.assumed is True
    assert "has not published" in kev.reason
    assert match_public_facing("Cisco ASA") == "Cisco ASA"
    plain = finalize_exposure(
        exposed=unresolved.exposed,
        reason=unresolved.reason,
        basis=unresolved.basis,
        public_facing_tag=None,
        in_kev=True,
        product_text="Windows Server",
    )
    assert plain.exposed is False
    assert plain.assumed is False
    not_kev = finalize_exposure(
        exposed=unresolved.exposed,
        reason=unresolved.reason,
        basis=unresolved.basis,
        public_facing_tag=None,
        in_kev=False,
        product_text="Cisco ASA",
    )
    assert not_kev.exposed is False


def test_operator_public_facing_tag_is_not_an_assumption():
    unresolved = infer_exposure(None, "10.1.1.8", "server")
    tagged = finalize_exposure(
        exposed=unresolved.exposed,
        reason=unresolved.reason,
        basis=unresolved.basis,
        public_facing_tag=True,
        in_kev=True,
        product_text="Internal wiki",
    )
    assert tagged.exposed is True
    assert tagged.assumed is False
    assert tagged.basis == "public_facing_tag"


def test_prioritize_marks_assumed_exposure_on_the_decision_path():
    findings = pd.DataFrame(
        [
            {
                "host_key": "edge.lab.invalid",
                "host_name": "edge.lab.invalid",
                "asset_name": "edge",
                "ip": "10.8.0.4",
                "operating_system": "PAN-OS",
                "system_type": "server",
                "owner": "Owen Park",
                "business_unit": "Edge Network",
                "exposed": False,
                "exposure_reason": "unresolved",
                "exposure_basis": "unresolved",
                "public_facing_tag": None,
                "cve": "CVE-2024-3400",
                "plugin_ids": "1",
                "plugin_name": "PAN-OS command injection",
                "severity": "Critical",
                "state": "open",
                "first_observed": date(2026, 10, 1),
                "last_seen": date(2026, 10, 16),
                "last_fixed": None,
                "raw_row_count": 1,
                "output": "synthetic",
                "solution": "patch",
                "port": "443",
                "protocol": "tcp",
                "cvss": 10.0,
                "cvss_vector": None,
                "scanner_epss": None,
            }
        ]
    )
    kev = {
        "CVE-2024-3400": {
            "cveID": "CVE-2024-3400",
            "vendorProject": "Palo Alto Networks",
            "product": "PAN-OS",
            "vulnerabilityName": "PAN-OS command injection",
            "dateAdded": "2024-04-12",
            "dueDate": "2024-04-19",
            "knownRansomwareCampaignUse": "Known",
            "forensicTriage": "Yes",
        }
    }
    frame = prioritize(findings, kev, {}, {}, date(2026, 10, 16))
    row = frame.iloc[0]
    assert bool(row["exposed"]) is True
    assert bool(row["exposure_assumed"]) is True
    assert "(assumed)" in row["decision_path"]
    assert "has not published" in row["assumption_notes"]
