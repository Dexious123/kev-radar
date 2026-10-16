"""MSRC CVRF parsing and the read-only PowerShell audit."""

from kev_radar.msrc import (
    extract_patches,
    microsoft_cves,
    remediation_violations,
    render_audit_script,
)

DOCUMENT = {
    "ProductTree": {
        "FullProductName": [
            {"ProductID": "11568", "Value": "Windows Server 2019"},
            {"ProductID": "11926", "Value": "Windows 11 Version 22H2"},
        ]
    },
    "Vulnerability": [
        {
            "CVE": "CVE-2021-34527",
            "Remediations": [
                {
                    "Description": {"Value": "5004947"},
                    "URL": "https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5004947",
                    "ProductID": ["11568"],
                    "Type": 2,
                    "FixedBuild": "10.0.17763.2029",
                    "RestartRequired": {"Value": "Yes"},
                    "SubType": "Security Update",
                },
                {
                    "Description": {"Value": "5004947"},
                    "URL": "https://support.microsoft.com/help/5004947",
                    "ProductID": ["11568"],
                    "Type": 3,
                    "SubType": "5004947",
                },
                {
                    "Description": {"Value": "KB5004950"},
                    "ProductID": "11926",
                    "Type": "2",
                    "FixedBuild": "10.0.22621.1992",
                },
            ],
        }
    ],
}


def test_extract_patches_keeps_vendor_fixes_only():
    patches = extract_patches(DOCUMENT, "CVE-2021-34527")
    by_kb = {item["kb"]: item for item in patches}
    assert set(by_kb) == {"KB5004947", "KB5004950"}
    assert by_kb["KB5004947"]["products"] == ["Windows Server 2019"]
    assert by_kb["KB5004947"]["fixed_builds"] == ["10.0.17763.2029"]
    assert by_kb["KB5004947"]["restart"] == "Yes"
    assert by_kb["KB5004950"]["products"] == ["Windows 11 Version 22H2"]


def test_microsoft_cve_selection():
    selected = microsoft_cves(
        [
            {"cve": "CVE-2021-34527", "vendor": "Microsoft", "product": "Windows", "name": "Print Spooler"},
            {"cve": "CVE-2021-44228", "vendor": "Apache", "product": "Log4j", "name": "Log4Shell"},
            {"cve": "not-a-cve", "vendor": "Microsoft", "product": "Windows", "name": "Skipped"},
        ]
    )
    assert selected == ["CVE-2021-34527"]


def test_audit_script_is_read_only_and_checks_hotfixes():
    script = render_audit_script(
        [
            {
                "cve": "CVE-2021-34527",
                "kb": "KB5004947",
                "products": ["Windows Server 2019"],
                "fixed_builds": ["10.0.17763.2029"],
            }
        ],
        hosts=["hl-win-srv-001.lab.invalid"],
    )
    assert "Get-HotFix" in script
    assert "Win32_QuickFixEngineering" in script
    assert "Get-CimInstance" in script
    assert "KB5004947" in script
    assert remediation_violations(script) == []
    assert "does not install, remove, download, or change anything" in script


def test_audit_script_drops_remediation_cmdlets_from_product_text():
    script = render_audit_script(
        [
            {
                "cve": "CVE-2021-34527",
                "kb": "5004947",
                "product": "Windows'; Install-WindowsUpdate; wusa.exe /uninstall",
                "fixed_build": "10.0.17763.2029",
            }
        ]
    )
    assert remediation_violations(script) == []
    assert "Install-WindowsUpdate" not in script
    assert "wusa" not in script.lower()
    assert "KB5004947" in script
