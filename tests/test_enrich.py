"""Live Vulnrichment lookups fall back when the GitHub record is missing."""

from kev_radar.enrich import supplement_ssvc, vulnrichment_url


def test_vulnrichment_url_uses_the_thousands_bucket():
    assert vulnrichment_url("CVE-2021-44228").endswith("/2021/44xxx/CVE-2021-44228.json")
    assert vulnrichment_url("cve-2024-3400").endswith("/2024/3xxx/CVE-2024-3400.json")
    assert "cisagov/vulnrichment" in vulnrichment_url("CVE-2023-27350")


def test_supplement_uses_live_rows_and_records_a_404():
    snapshot = {"CVE-2024-0001": {"automatable": "yes", "technical_impact": "partial"}}

    def fetch(cve: str) -> dict:
        if cve == "CVE-2024-9999":
            return {"found": False}
        if cve == "CVE-2024-8888":
            raise RuntimeError("network down")
        return {
            "found": True,
            "automatable": "no",
            "technical_impact": "total",
            "exploitation": "none",
            "cvss": 7.5,
        }

    merged, report = supplement_ssvc(
        snapshot,
        ["CVE-2024-0001", "CVE-2024-2222", "CVE-2024-9999", "CVE-2024-8888"],
        fetch=fetch,
        limit=10,
    )
    assert merged["CVE-2024-0001"]["automatable"] == "yes"
    assert merged["CVE-2024-2222"]["technical_impact"] == "total"
    assert "CVE-2024-9999" not in merged
    assert report["fetched"] == ["CVE-2024-2222"]
    assert report["not_published"] == ["CVE-2024-9999"]
    assert report["failed"] == ["CVE-2024-8888"]


def test_supplement_stops_at_the_live_limit():
    def fetch(cve: str) -> dict:
        return {"found": True, "automatable": "yes", "technical_impact": "partial"}

    merged, report = supplement_ssvc({}, ["CVE-2024-1000", "CVE-2024-1001", "CVE-2024-1002"], fetch=fetch, limit=1)
    assert report["fetched"] == ["CVE-2024-1000"]
    assert report["skipped"] == ["CVE-2024-1001", "CVE-2024-1002"]
    assert "CVE-2024-1001" not in merged
