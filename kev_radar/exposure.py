"""BOD 26-04 asset exposure, including the generally-public-facing step.

Implementation guidance FAQ, "What is the protocol when an information item
about a vulnerable asset is not available?" (page updated August 25, 2026):

1. A publicly routable address is public.
2. Else an asset-type tag of "network" is public.
3. Else, for a KEV-listed CVE, if CISA's analysis says the affected software
   is generally public-facing, treat the asset as public.
4. Else treat the asset as internal.

An explicit Internet Exposed tag still wins, including an explicit No on a
public address. That is the agency's own attestation, which the same FAQ
tells agencies to provide.

CISA has not published the product list behind step 3. When the earlier
steps do not decide, KEV Radar matches a short list of edge and
remote-access product names and marks the row assumed. An operator column
or tag named generally public-facing is an attestation, not an assumption.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Longer phrases first so "cisco asa" wins over a generic token.
_MARKERS: tuple[tuple[str, str], ...] = (
    ("adaptive security appliance", "Cisco ASA"),
    ("remote desktop gateway", "Remote Desktop Gateway"),
    ("ivanti connect", "Ivanti Connect Secure"),
    ("pulse connect", "Pulse Connect Secure"),
    ("pulse secure", "Pulse Secure"),
    ("citrix gateway", "Citrix Gateway"),
    ("citrix adc", "Citrix ADC"),
    ("exchange server", "Exchange Server"),
    ("outlook web", "Outlook Web Access"),
    ("vmware horizon", "VMware Horizon"),
    ("globalprotect", "GlobalProtect"),
    ("anyconnect", "AnyConnect"),
    ("sonicwall", "SonicWall"),
    ("watchguard", "WatchGuard"),
    ("netscaler", "NetScaler"),
    ("coldfusion", "ColdFusion"),
    ("sharepoint", "SharePoint"),
    ("wordpress", "WordPress"),
    ("fortigate", "FortiGate"),
    ("fortios", "FortiOS"),
    ("cisco asa", "Cisco ASA"),
    ("pan-os", "PAN-OS"),
    ("palo alto", "Palo Alto"),
    ("big-ip", "F5 BIG-IP"),
    ("moveit", "MOVEit"),
    ("firewall", "firewall"),
    ("vpn", "VPN"),
)


@dataclass(frozen=True)
class ExposureResult:
    exposed: bool
    reason: str
    basis: str
    assumed: bool


def match_public_facing(*parts: object) -> str | None:
    """Return the edge-product label when the text matches the stand-in list."""
    blob = " ".join(str(part or "") for part in parts).lower()
    if not blob.strip():
        return None
    for needle, label in _MARKERS:
        if re.search(rf"(?<![a-z0-9]){re.escape(needle)}(?![a-z0-9])", blob):
            return label
    return None


def finalize_exposure(
    *,
    exposed: bool,
    reason: str,
    basis: str,
    public_facing_tag: bool | None,
    in_kev: bool,
    product_text: str,
) -> ExposureResult:
    """Apply step 3 only when the tag, address, and asset type did not decide."""
    if basis != "unresolved":
        return ExposureResult(bool(exposed), reason, basis, False)
    if public_facing_tag is True and in_kev:
        return ExposureResult(
            True,
            "No exposure tag, public address, or network asset type. "
            "The export marks this software generally public-facing, so "
            "the implementation guidance's generally-public-facing rule treats the asset as public.",
            "public_facing_tag",
            False,
        )
    if public_facing_tag is False:
        return ExposureResult(
            False,
            "No exposure tag, public address, or network asset type. "
            "The export says the software is not generally public-facing, "
            "so the asset stays internal.",
            "public_facing_tag",
            False,
        )
    if in_kev:
        matched = match_public_facing(product_text)
        if matched:
            return ExposureResult(
                True,
                "No exposure tag, public address, or network asset type. "
                "CISA has not published which products its analysis treats as "
                f"generally public-facing. KEV Radar's labeled edge-software list "
                f"matched {matched}, so exposure is assumed public. "
                "Set an Internet Exposed tag to override this.",
                "public_facing_heuristic",
                True,
            )
    return ExposureResult(
        False,
        "No exposure tag, no public address, and asset type is not network. "
        "The implementation guidance's generally-public-facing rule did not apply, "
        "so the asset is internal.",
        "internal",
        False,
    )
