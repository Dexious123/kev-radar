"""Untrusted text stays inert: no Markdown images or links where it is shown, no live formulas where it is saved."""

import csv
import io
from datetime import date

import pandas as pd

from kev_radar.briefing import check_text, render_offline
from kev_radar.exceptions import exceptions_from_csv, exceptions_to_csv, record_from_dict
from kev_radar.kevdiff import WeekItem, render_monday_report
from kev_radar.present import csv_download
from kev_radar.report import render_tickets
from kev_radar.textsafe import from_spreadsheet_cell, md_text, md_without_images, spreadsheet_cell

BEACON = "![t](https://beacon.example.invalid/x.png)"
LINK = "[Login](javascript:alert(1))"


def test_markdown_constructs_are_escaped_and_host_names_are_not():
    assert md_text(BEACON) == r"\!\[t\](https://beacon.example.invalid/x.png)"
    assert md_text(LINK).startswith(r"\[Login\]")
    assert md_text("<b>x</b> $x$ `y` a|b ~z~ *k*") == r"\<b\>x\</b\> \$x\$ \`y\` a\|b \~z\~ \*k\*"
    assert md_text("hl-pay-ws_010.lab.invalid") == "hl-pay-ws_010.lab.invalid"
    assert md_text("two\nlines\r\n  here") == "two lines here"
    assert md_text(None) == ""


def test_a_whole_draft_keeps_its_links_but_loses_its_images():
    draft = f"See {LINK} and {BEACON} and ![a][1]"
    out = md_without_images(draft)
    assert "![" not in out and out.count(r"!\[") == 2
    assert "[Login]" in out


def test_formula_cells_are_quoted_and_unquoted_again():
    for value in ("=1+1", "+cmd", "-x", "@SUM(1)", "\tx"):
        assert spreadsheet_cell(value) == "'" + value
        assert from_spreadsheet_cell(spreadsheet_cell(value)) == value
    assert spreadsheet_cell(-4) == -4 and spreadsheet_cell(3.5) == 3.5
    assert spreadsheet_cell("2026-10-18") == "2026-10-18"
    assert from_spreadsheet_cell("'plain") == "'plain"


def test_the_findings_csv_has_no_live_formulas():
    frame = pd.DataFrame({"owner": ['=HYPERLINK("https://x","y")', "Ada"], "days_left": [-4, 3]})
    rows = list(csv.reader(io.StringIO(csv_download(frame))))
    assert rows[1][0].startswith("'=") and rows[1][1] == "-4"
    assert rows[2] == ["Ada", "3"]


def test_the_exceptions_register_round_trips_formula_text():
    record = record_from_dict(
        {
            "exception_id": "EX-1", "host_name": "h", "cve": "CVE-2024-3400", "owner": "=1+1",
            "justification": "@SUM(1)", "compensating_controls": "+cmd", "expiry": "2026-12-01", "approver": "-x",
        }
    )
    text = exceptions_to_csv([record])
    row = list(csv.reader(io.StringIO(text)))[1]
    assert not any(cell[:1] in ("=", "+", "-", "@") for cell in row)
    back, errors = exceptions_from_csv(text)
    assert errors == [] and back[0].owner == "=1+1" and back[0].approver == "-x"


def _findings() -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "state": "open", "cve": "CVE-2024-3400", "host_name": "h1.lab.invalid", "owner": f"Owner {BEACON}",
                "business_unit": f"Unit {LINK}", "sla_status": "Overdue", "deadline": date(2026, 10, 1), "score": 90.0,
                "band": "Critical", "forensics_required": True, "decision_path": "KEV=Yes → 3 days",
                "score_summary": f"Why {BEACON}", "sla_paused": False,
            }
        ]
    )


def test_tickets_carry_no_live_images_or_links():
    tickets = render_tickets(_findings(), date(2026, 10, 18))
    assert "![" not in tickets and "[Login]" not in tickets
    assert r"\!\[t\]" in tickets


def test_the_monday_note_escapes_feed_text():
    item = WeekItem(
        cve="CVE-2024-3400", name=f"Name {BEACON}", vendor="V", product=f"P {LINK}", date_added=date(2026, 10, 14),
        due_date=None, ransomware=False, triage="no", required_action="", in_estate=False,
    )
    note = render_monday_report(catalog_version="2026.10.18", as_of=date(2026, 10, 18), items=[item], estate_name=f"E {BEACON}")
    assert "![" not in note and "[Login]" not in note


def test_the_offline_briefing_escapes_names_and_still_passes_its_checker():
    facts = {
        "estate": "Uploaded export", "as_of": "2026-10-18", "directive": "BOD 26-04", "open_findings": 1, "overdue": 1,
        "due_in_window": 0, "window_days": 7, "weekly_close_rate": 0.0, "history_weeks": 4, "projected_misses": 0,
        "slo_percent": 0.0, "average_days_to_fix": None, "active_exceptions": 0, "expired_exceptions": 0,
        "findings": [
            {"cve": "CVE-2024-3400", "host_name": "h1.lab.invalid", "owner": f"Owner {BEACON}", "business_unit": f"Unit {LINK}",
             "deadline": "2026-10-01", "score": 90.0, "sla_status": "Overdue"}
        ],
        "exceptions": [],
    }
    markdown = render_offline(facts)["markdown"]
    assert "![" not in markdown and "[Login]" not in markdown
    assert check_text(markdown, facts).passed
