"""Flight strips for the top of the queue."""

from datetime import date, timedelta

import pandas as pd

from kev_radar.strips import render_strips

AS_OF = date(2026, 10, 17)


def _top(rows):
    return pd.DataFrame(rows, columns=["cve", "host_name", "owner", "business_unit", "deadline", "reason"])


def test_strips_keep_queue_order_and_mark_the_deadline_band():
    html = render_strips(
        _top(
            [
                ["CVE-2026-0001", "a.lab.invalid", "Owen Park", "Edge Network", AS_OF - timedelta(days=1), "1 day overdue"],
                ["CVE-2026-0002", "b.lab.invalid", "Priya Shah", "Payments", AS_OF + timedelta(days=1), "due in 1 day"],
                ["CVE-2026-0003", "c.lab.invalid", "Amira Haddad", "Claims", AS_OF + timedelta(days=45), "high score"],
            ]
        ),
        AS_OF,
    )
    assert html.startswith('<ol class="strips">')
    assert html.index("CVE-2026-0001") < html.index("CVE-2026-0002") < html.index("CVE-2026-0003")
    assert '<li class="strip past">' in html and '<li class="strip near">' in html and '<li class="strip far">' in html
    assert "1 day past due" in html and "Due in 1 day" in html and "Due in 45 days" in html


def test_the_reason_drops_the_timing_the_strip_already_shows():
    html = render_strips(
        _top([["CVE-2026-0001", "h", "o", "u", AS_OF - timedelta(days=3), "3 days overdue · forensic triage required · EPSS 97%"]]),
        AS_OF,
    )
    why = html.split('class="s-why">')[1]
    assert why.startswith("forensic triage required, EPSS 97%")
    assert "3 days overdue" not in why


def test_strip_text_is_escaped():
    html = render_strips(
        _top([["CVE-2026-0001", "<img src=x onerror=alert(1)>", "<b>x</b>", "BU", AS_OF, "<i>why</i>"]]), AS_OF
    )
    assert "<img" not in html and "<b>x</b>" not in html and "<i>why</i>" not in html
    assert "&lt;img" in html


def test_no_deadline_and_empty_queue():
    assert render_strips(_top([]), AS_OF) == ""
    html = render_strips(_top([["CVE-2026-0001", "h", "o", "u", None, "fix on upgrade"]]), AS_OF)
    assert "No fixed deadline" in html
