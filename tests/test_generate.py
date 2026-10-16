"""Synthetic estate: fictional hosts, real CVE IDs, Tenable column names."""

from datetime import date
from io import StringIO

from kev_radar.generate import generate_csv
from kev_radar.parse import is_public_routable, parse_findings

POOL = [
    {
        "cve": "CVE-2021-44228",
        "vendor": "Apache",
        "product": "Log4j",
        "name": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP",
        "family": "linux",
        "in_kev": True,
        "ransomware": True,
        "date_added": "2026-10-14",
        "cvss": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "epss": 0.97,
    },
    {
        "cve": "CVE-2024-12345",
        "vendor": "Example",
        "product": "Widget",
        "name": "Example widget overflow",
        "family": "windows",
        "in_kev": False,
        "ransomware": False,
        "date_added": None,
        "cvss": 6.5,
        "cvss_vector": None,
        "epss": 0.02,
    },
    {
        "cve": "CVE-2023-0001",
        "vendor": "Cisco",
        "product": "IOS XE",
        "name": "Cisco IOS XE web UI",
        "family": "network",
        "in_kev": True,
        "ransomware": False,
        "date_added": "2023-10-01",
        "cvss": 9.8,
        "epss": 0.8,
    },
]


def test_generated_export_parses_and_stays_fictional():
    csv_text = generate_csv(POOL, as_of=date(2026, 10, 16), seed=2604, host_count=24)
    result = parse_findings(StringIO(csv_text))
    assert result.raw_rows > result.collapsed_findings
    assert result.collapsed_findings > 24
    hosts = set(result.findings["host_name"])
    assert hosts
    assert all(name.endswith(".lab.invalid") for name in hosts)
    assert all(not is_public_routable(ip) for ip in result.findings["ip"])
    assert set(result.findings["owner"]) <= {
        "Priya Shah",
        "Luis Ortega",
        "Amira Haddad",
        "Jonah Reid",
        "Noah Berger",
        "Hannah Brooks",
        "Marcus Chen",
        "Elena Voss",
        "Sofia Almeida",
        "Owen Park",
    }
    week = result.findings[result.findings["cve"] == "CVE-2021-44228"]
    assert not week.empty
    assert "Synthetic" in week.iloc[0]["output"]
