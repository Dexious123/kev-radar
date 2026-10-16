"""Executive HTML and Markdown tickets stay inside the queue's facts."""

from datetime import date, timedelta

import pandas as pd

from kev_radar.report import render_html_report, render_tickets

AS_OF = date(2026, 10, 16)


def _frame() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "state": "open",
                "cve": "CVE-2024-1111",
                "host_name": "pay.lab.invalid",
                "owner": "Priya Shah",
                "business_unit": "Payments",
                "sla_status": "Overdue",
                "sla_paused": False,
                "score": 88.0,
                "band": "Critical",
                "deadline": AS_OF - timedelta(days=2),
                "forensics_required": True,
                "decision_path": "KEV=Yes → Exposed=Yes → Automatable=No → Total impact → 3 days + forensic triage",
                "score_summary": "KEV 35 + ransomware 10",
                "reason": "2 days overdue · forensic triage required",
            }
        ]
    )


def _stats() -> dict:
    class Forecast:
        already_overdue = 1
        due_in_window = 0
        projected_misses = 0
        weekly_close_rate = 1.5
        statement = "Projection, not a prediction. About 0 of the 0 findings due in the next 7 days."

    return {
        "open": 1,
        "overdue": 1,
        "due_soon": 0,
        "mttr": 12,
        "active_exceptions": 0,
        "slo": {"percent": 40.0, "eligible": 10, "compliant": 4},
        "forecast": Forecast(),
    }


def test_html_report_contains_the_queue_and_the_directive():
    top = _frame()
    html = render_html_report(_frame(), _stats(), top, AS_OF)
    assert "CVE-2024-1111" in html
    assert "pay.lab.invalid" in html
    assert "2 days overdue" in html
    assert "bod-26-04-prioritizing-security-updates-based-risk" in html
    assert "CVE-1999-0001" not in html
    assert "Projection, not a prediction" in html


def test_markdown_tickets_are_issue_shaped():
    text = render_tickets(_frame(), AS_OF)
    assert "## CVE-2024-1111 on pay.lab.invalid" in text
    assert "Forensic triage required by the BOD path:** Yes" in text
    assert "- [ ] Patch, mitigate, or remove" in text
    assert "Priya Shah" in text
