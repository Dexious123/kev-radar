"""Map a CVE's vendor and product text onto a synthetic host family."""

from __future__ import annotations

_WINDOWS = (
    "microsoft",
    "windows",
    "exchange",
    "sharepoint",
    "office",
    "outlook",
    "iis",
    ".net",
    "active directory",
)
_NETWORK = (
    "fortinet",
    "fortios",
    "fortigate",
    "palo alto",
    "pan-os",
    "panos",
    "cisco",
    "juniper",
    "ivanti",
    "citrix",
    "pulse secure",
    "sonicwall",
    "f5",
    "vpn",
    "firewall",
    "beyondtrust",
    "netscaler",
    "barracuda",
    "watchguard",
)
_LINUX = (
    "linux",
    "kernel",
    "ubuntu",
    "red hat",
    "rhel",
    "debian",
    "apache",
    "nginx",
    "openssl",
    "openssh",
    "sudo",
    "vmware",
    "esxi",
)
_WORKSTATION = (
    "chrome",
    "adobe",
    "apple",
    "macos",
    "ios",
    "android",
    "firefox",
    "acrobat",
)


def family_for(*parts: str) -> str:
    """Return windows, network, linux, workstation, or any."""
    text = " ".join(part for part in parts if part).lower()
    if any(token in text for token in _NETWORK):
        return "network"
    if any(token in text for token in _WINDOWS):
        return "windows"
    if any(token in text for token in _LINUX):
        return "linux"
    if any(token in text for token in _WORKSTATION):
        return "workstation"
    return "any"
