"""Tenable-style CSV parsing, CVE collapse, and exposure inference."""

from datetime import date
from io import StringIO

import pytest

from kev_radar.parse import ParseError, infer_exposure, is_public_routable, parse_findings

TENABLE = """\
definition.id,definition.name,definition.cve,definition.cvss3.base_score,severity,state,first_observed,last_seen,last_fixed,port,protocol,output,asset.name,asset.host_name,asset.display_ipv4_address,asset.operating_system,asset.system_type,asset.tags
9000001,Log4Shell,CVE-2021-44228,10.0,critical,OPEN,2026-09-01T12:00:00Z,2026-10-15T12:00:00Z,,443,tcp,ldap lookup,pay-web,pay-web.lab.invalid,10.4.0.12,Ubuntu 24.04,server,"{""Owner"": [""Priya Shah""], ""Business Unit"": [""Payments""], ""Internet Exposed"": [""Yes""]}"
9000001,Log4Shell,CVE-2021-44228,10.0,critical,FIXED,2026-08-01T12:00:00Z,2026-09-20T12:00:00Z,2026-09-20T12:00:00Z,8443,tcp,second plugin row,pay-web,pay-web.lab.invalid,10.4.0.12,Ubuntu 24.04,server,"{""Owner"": [""Priya Shah""], ""Business Unit"": [""Payments""], ""Internet Exposed"": [""Yes""]}"
9000002,Two CVEs,CVE-2024-0001 CVE-2024-0002,7.5,high,OPEN,2026-10-01T00:00:00Z,2026-10-16T00:00:00Z,,22,tcp,banner,edge-1,edge-1.lab.invalid,203.0.113.10,PAN-OS,network,Owner:Owen Park|Business Unit:Edge Network|Internet Exposed:No
9000003,No identifier, ,5.0,medium,OPEN,2026-10-01T00:00:00Z,2026-10-16T00:00:00Z,,80,tcp,config only,,missing.lab.invalid,10.1.1.1,Linux,server,
"""

NESSUS = """\
Plugin ID,CVE,CVSS v3.0 Base Score,Risk,Host,Name,First Found,Last Found,Plugin Output
19506,CVE-2019-0708,9.8,Critical,8.8.8.8,BlueKeep,2026-07-04,2026-10-01,rdp
"""


def test_tenable_keys_collapse_and_tags():
    result = parse_findings(StringIO(TENABLE))
    assert result.raw_rows == 4
    assert result.skipped_no_cve == 1
    assert result.duplicate_rows == 1
    log4 = result.findings[result.findings["cve"] == "CVE-2021-44228"].iloc[0]
    assert log4["state"] == "open"  # an open row keeps the finding open
    assert log4["first_observed"] == date(2026, 8, 1)  # earliest
    assert log4["owner"] == "Priya Shah"
    assert log4["business_unit"] == "Payments"
    assert bool(log4["exposed"]) is True
    assert "Exposure tag" in log4["exposure_reason"]
    assert "443" in log4["port"] and "8443" in log4["port"]
    assert result.collapsed_findings == 3  # log4j + two exploded CVEs


def test_multi_cve_cell_and_pipe_tags():
    result = parse_findings(StringIO(TENABLE))
    edge = result.findings[result.findings["host_key"] == "edge-1.lab.invalid"]
    assert set(edge["cve"]) == {"CVE-2024-0001", "CVE-2024-0002"}
    assert set(edge["owner"]) == {"Owen Park"}
    assert set(edge["business_unit"]) == {"Edge Network"}
    # Tag explicitly says not exposed, even though the address is documentation space.
    assert set(edge["exposed"]) == {False}


def test_nessus_headers_and_public_ip_fallback():
    result = parse_findings(StringIO(NESSUS))
    row = result.findings.iloc[0]
    assert row["cve"] == "CVE-2019-0708"
    assert row["severity"] == "Critical"
    assert row["cvss"] == 9.8
    assert row["host_name"] == "8.8.8.8"
    assert bool(row["exposed"]) is True
    assert "publicly routable" in row["exposure_reason"]
    assert row["state"] == "open"
    assert row["first_observed"] == date(2026, 7, 4)


def test_rejects_unrelated_csv():
    with pytest.raises(ParseError):
        parse_findings(StringIO("name,count\napples,3\n"))


def test_exposure_rules():
    assert is_public_routable("8.8.8.8") is True
    assert is_public_routable("10.1.1.1") is False
    assert is_public_routable("203.0.113.5") is False  # documentation range
    assert infer_exposure(True, "10.0.0.5", "server")[0] is True
    assert infer_exposure(None, "10.0.0.5", "network")[0] is True
    assert infer_exposure(None, "10.0.0.5", "server")[0] is False
    assert infer_exposure(False, "8.8.8.8", "network")[0] is False
