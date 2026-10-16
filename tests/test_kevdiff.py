"""KEV this week, ransomware flag, and a missing forensicTriage field."""

from datetime import date

from kev_radar.kevdiff import (
    EstateHit,
    kev_this_week,
    render_monday_report,
    triage_status,
)

AS_OF = date(2026, 10, 16)


def _entry(**overrides):
    base = {
        "cveID": "CVE-2026-1000",
        "vendorProject": "Example",
        "product": "Gateway",
        "vulnerabilityName": "Example bug",
        "dateAdded": "2026-10-14",
        "dueDate": "2026-10-17",
        "knownRansomwareCampaignUse": "Unknown",
        "requiredAction": "Apply the vendor update.",
    }
    base.update(overrides)
    return base


def test_missing_forensic_triage_field_is_not_an_error():
    assert triage_status(_entry()) == "not_in_feed"
    assert triage_status(_entry(forensicTriage="Yes")) == "yes"
    assert triage_status(_entry(forensicTriage="No")) == "no"
    assert triage_status(_entry(forensicTriage="")) == "not_in_feed"
    assert triage_status(_entry(forensicTriage="maybe")) == "unrecognized"


def test_week_diff_intersects_the_estate_and_flags_ransomware():
    current = [
        _entry(cveID="CVE-2026-1000", forensicTriage="Yes", knownRansomwareCampaignUse="Known"),
        _entry(cveID="CVE-2026-1001", dateAdded="2026-10-08", forensicTriage="No"),
        _entry(cveID="CVE-2026-1002", dateAdded="2026-10-16"),
    ]
    previous = [_entry(cveID="CVE-2020-0001", dateAdded="2020-01-01")]
    estate = {
        "CVE-2026-1000": [
            EstateHit("edge-1.lab.invalid", "Owen Park", "Edge Network", True, "open"),
            EstateHit("edge-2.lab.invalid", "Owen Park", "Edge Network", False, "open"),
        ]
    }
    report = kev_this_week(current, previous, estate, AS_OF, window_days=7)
    week = {item.cve: item for item in report["this_week"]}
    # Oct 10–16 inclusive. Oct 8 is outside the window.
    assert set(week) == {"CVE-2026-1000", "CVE-2026-1002"}
    hit = week["CVE-2026-1000"]
    assert hit.in_estate is True
    assert hit.ransomware is True
    assert hit.triage == "yes"
    assert hit.host_count == 2
    assert hit.exposed_host_count == 1
    assert week["CVE-2026-1002"].in_estate is False
    # Previous snapshot is missing all three, but the two in-window CVEs are not repeated.
    assert [item.cve for item in report["snapshot_only"]] == ["CVE-2026-1001"]


def test_monday_report_mentions_triage_gap():
    current = [_entry()]
    report = kev_this_week(current, None, {}, AS_OF)
    text = render_monday_report(
        catalog_version="2026.10.16",
        as_of=AS_OF,
        items=report["this_week"],
    )
    assert "forensicTriage: Not in this feed" in text
    assert "CVE-2026-1000" in text
    assert "Not in this estate" in text
