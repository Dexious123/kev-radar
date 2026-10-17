"""Map CVEs to Microsoft KB articles with the MSRC CVRF API.

The dashboard reads ``data/snapshots/msrc_kb.json``. A live call is only for a
CVE the snapshot does not already contain. If that call fails, the snapshot
(or an empty result) is what the page shows.

The generated PowerShell only reads installed hotfixes. It does not install,
remove, or change a system.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

import requests

UPDATES_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/Updates/{cve}"
CVRF_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{document_id}"
VENDOR_FIX = 2

# Cmdlets and programs that would change a host. The audit script is rejected
# if any of these appear. Matching is case-insensitive.
REMEDIATION_CMDLETS = (
    "Install-WindowsUpdate",
    "Get-WindowsUpdate",
    "Install-Package",
    "Install-Module",
    "Uninstall-Package",
    "Uninstall-WindowsFeature",
    "Add-WindowsPackage",
    "Remove-WindowsPackage",
    "Add-WindowsCapability",
    "Remove-WindowsCapability",
    "Enable-WindowsOptionalFeature",
    "Disable-WindowsOptionalFeature",
    "Restart-Computer",
    "Stop-Computer",
    "Invoke-Expression",
    "Invoke-WebRequest",
    "Invoke-RestMethod",
    "Invoke-Command",
    "Start-Process",
    "Set-ExecutionPolicy",
    "New-Item",
    "Set-Item",
    "Remove-Item",
    "Set-Content",
    "Add-Content",
    "Clear-Content",
    "Out-File",
    "Start-Service",
    "Stop-Service",
    "Restart-Service",
    "Set-Service",
    "Enter-PSSession",
    "wusa",
    "dism",
    "msiexec",
    "schtasks",
    "DownloadString",
)

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_KB_RE = re.compile(r"^KB\d{4,}$", re.IGNORECASE)
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$")


def normalize_kb(value: object) -> str | None:
    digits = re.sub(r"\D", "", str(value or ""))
    if len(digits) < 5:
        return None
    return "KB" + digits


def _text(value: object) -> str:
    if isinstance(value, dict):
        return str(value.get("Value") or "")
    return str(value or "")


def _product_ids(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def extract_patches(document: dict, cve: str) -> list[dict]:
    """Vendor-fix KB articles for one CVE inside a CVRF document.

    Remediation type 2 is the vendor fix. Other types (knowledge-base links,
    workarounds) are not patches and are left out.
    """
    names: dict[str, str] = {}
    tree = document.get("ProductTree") or {}
    for item in tree.get("FullProductName") or []:
        if isinstance(item, dict) and item.get("ProductID") is not None:
            names[str(item["ProductID"])] = str(item.get("Value") or "")
    wanted = cve.upper()
    grouped: dict[str, dict] = {}
    for vuln in document.get("Vulnerability") or []:
        if str(vuln.get("CVE") or "").upper() != wanted:
            continue
        for remediation in vuln.get("Remediations") or []:
            try:
                kind = int(remediation.get("Type"))
            except (TypeError, ValueError):
                continue
            if kind != VENDOR_FIX:
                continue
            kb = normalize_kb(_text(remediation.get("Description")))
            if kb is None:
                continue
            bucket = grouped.setdefault(
                kb,
                {
                    "kb": kb,
                    "products": [],
                    "fixed_builds": [],
                    "url": "",
                    "restart": "",
                },
            )
            url = str(remediation.get("URL") or "")
            if url and not bucket["url"]:
                bucket["url"] = url
            restart = _text(remediation.get("RestartRequired"))
            if restart and not bucket["restart"]:
                bucket["restart"] = restart
            build = str(remediation.get("FixedBuild") or "").strip()
            if build and build not in bucket["fixed_builds"]:
                bucket["fixed_builds"].append(build)
            for product_id in _product_ids(remediation.get("ProductID")):
                product = names.get(product_id) or product_id
                if product and product not in bucket["products"]:
                    bucket["products"].append(product)
    patches = []
    for kb in sorted(grouped):
        bucket = grouped[kb]
        patches.append(
            {
                "kb": bucket["kb"],
                "products": bucket["products"][:8],
                "product_count": len(bucket["products"]),
                "fixed_builds": bucket["fixed_builds"][:8],
                "url": bucket["url"],
                "restart": bucket["restart"],
            }
        )
    return patches


def microsoft_cves(records: list[dict]) -> list[str]:
    """CVE IDs whose vendor, product, or name refers to Microsoft or Windows."""
    found: list[str] = []
    for record in records:
        blob = " ".join(
            str(record.get(key) or "") for key in ("vendor", "product", "name", "kev_vendor", "kev_product", "vuln_name")
        ).lower()
        if "microsoft" not in blob and "windows" not in blob:
            continue
        cve = str(record.get("cve") or record.get("cveID") or "").upper()
        if _CVE_RE.match(cve):
            found.append(cve)
    return sorted(set(found))


def _get_json(url: str, *, timeout: float) -> dict:
    response = requests.get(
        url,
        timeout=timeout,
        headers={
            "User-Agent": "kev-radar/1.0 (+https://github.com/Dexious123/kev-radar)",
            "Accept": "application/json",
        },
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise ValueError(f"Unexpected MSRC payload from {url}")
    return payload


def lookup_cve_live(cve: str, *, timeout: float = 40, document_cache: dict | None = None) -> dict:
    """Fetch one CVE from the CVRF API. A 404 is an empty patch list, not an error."""
    cve = cve.upper()
    if not _CVE_RE.match(cve):
        raise ValueError(f"Not a CVE id: {cve}")
    try:
        listing = _get_json(UPDATES_URL.format(cve=cve), timeout=timeout)
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else None
        if status == 404:
            return {
                "document_id": None,
                "document_title": "",
                "patches": [],
                "source": "live",
                "note": "MSRC has no security update for this CVE.",
            }
        raise
    values = listing.get("value") or []
    if not values:
        return {
            "document_id": None,
            "document_title": "",
            "patches": [],
            "source": "live",
            "note": "MSRC has no security update for this CVE.",
        }
    first = values[0]
    document_id = str(first.get("ID") or "")
    cache = document_cache if document_cache is not None else {}
    document = cache.get(document_id)
    if document is None:
        document = _get_json(CVRF_URL.format(document_id=document_id), timeout=max(timeout, 90))
        cache[document_id] = document
    return {
        "document_id": document_id,
        "document_title": str(first.get("DocumentTitle") or ""),
        "patches": extract_patches(document, cve),
        "source": "live",
        "note": "",
    }


def build_kb_snapshot(cves: list[str], *, timeout: float = 40) -> dict:
    """Download KB articles for the given CVEs. One CVRF document is fetched once."""
    documents: dict[str, dict] = {}
    mapped: dict[str, dict] = {}
    for cve in sorted({item.upper() for item in cves if _CVE_RE.match(item.upper())}):
        try:
            mapped[cve] = lookup_cve_live(cve, timeout=timeout, document_cache=documents)
        except (requests.RequestException, ValueError) as exc:
            mapped[cve] = {
                "document_id": None,
                "document_title": "",
                "patches": [],
                "source": "live-error",
                "note": str(exc)[:240],
            }
        print(f"msrc {cve}: {len(mapped[cve]['patches'])} KB articles ({mapped[cve].get('document_id') or mapped[cve].get('note')})")
    return {
        "fetched_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "https://api.msrc.microsoft.com/cvrf/v3.0/",
        "cve_count": len(mapped),
        "patch_count": sum(len(entry.get("patches") or []) for entry in mapped.values()),
        "cves": mapped,
    }


def patches_for(snapshot: dict, cve: str) -> list[dict]:
    entry = (snapshot.get("cves") or {}).get(str(cve).upper()) or {}
    patches = entry.get("patches") or []
    return list(patches)


def is_windows_text(*parts: object) -> bool:
    blob = " ".join(str(part or "") for part in parts).lower()
    return "microsoft" in blob or "windows" in blob


def remediation_violations(script: str) -> list[str]:
    """Return remediation cmdlets present in ``script``."""
    found = []
    for name in REMEDIATION_CMDLETS:
        if re.search(rf"(?i)(?<![A-Za-z0-9-]){re.escape(name)}(?![A-Za-z0-9-])", script):
            found.append(name)
    return found


def _executable_text(script: str) -> str:
    """The lines PowerShell would execute: comments and here-string data removed.

    Host names may only appear in comments and are restricted to
    ``[A-Za-z0-9.-]``; table fields cannot contain a quote, ``@`` or a newline.
    Neither can leave its line, so a host called ``wusa`` is text, not a
    command, and must not make the script refuse itself.
    """
    kept: list[str] = []
    in_data = False
    for line in script.splitlines():
        stripped = line.strip()
        if in_data:
            if stripped.startswith("'@"):
                in_data = False
                kept.append(line)
            continue
        if stripped.endswith("@'"):
            in_data = True
            kept.append(line)
            continue
        if stripped.startswith("#"):
            continue
        kept.append(line)
    return "\n".join(kept)


def _sanitize_field(value: object, *, pattern: str) -> str:
    text = re.sub(pattern, " ", str(value or ""))
    for name in REMEDIATION_CMDLETS:
        text = re.sub(re.escape(name), " ", text, flags=re.IGNORECASE)
    return " ".join(text.split())


def render_audit_script(rows: list[dict], *, hosts: list[str] | None = None) -> str:
    """Read-only hotfix audit. Rows need ``cve`` and ``kb``.

    Data is emitted as CSV text and parsed with ConvertFrom-Csv, so a product
    name cannot become a command. Host names are comments, not parameters.
    """
    lines = [
        "# KEV Radar read-only hotfix audit.",
        "# Reports whether each KB is installed on THIS computer.",
        "# It does not install, remove, download, or change anything.",
        "# Run it on each Windows host listed in the comments.",
        "",
    ]
    seen_hosts: list[str] = []
    for host in hosts or []:
        cleaned = str(host).strip()
        if _HOST_RE.match(cleaned) and cleaned not in seen_hosts:
            seen_hosts.append(cleaned)
    if seen_hosts:
        lines.append("# Hosts in the export that carry these CVEs:")
        shown = seen_hosts[:80]
        lines.extend(f"# - {host}" for host in shown)
        if len(seen_hosts) > len(shown):
            lines.append(f"# - and {len(seen_hosts) - len(shown)} more hosts in the export")
        lines.append("")
    table = ["CVE,KB,Product,FixedBuild"]
    emitted: set[tuple[str, str]] = set()
    for row in rows:
        cve = str(row.get("cve") or "").upper()
        kb = normalize_kb(row.get("kb"))
        if not _CVE_RE.match(cve) or kb is None:
            continue
        if (cve, kb) in emitted:
            continue
        emitted.add((cve, kb))
        product = _sanitize_field(row.get("product") or row.get("products") or "", pattern=r"[^A-Za-z0-9 .()/_+-]")
        build = _sanitize_field(row.get("fixed_build") or row.get("fixed_builds") or "", pattern=r"[^A-Za-z0-9.]")
        if isinstance(row.get("products"), list) and not product:
            product = _sanitize_field("; ".join(str(item) for item in row["products"][:4]), pattern=r"[^A-Za-z0-9 .()/_+-]")
        if isinstance(row.get("fixed_builds"), list) and not build:
            build = _sanitize_field(" ".join(str(item) for item in row["fixed_builds"][:4]), pattern=r"[^A-Za-z0-9.]")
        product = product.replace(",", ";")
        table.append(f"{cve},{kb},{product},{build}")
    lines.extend(
        [
            "$catalog = @'",
            *table,
            "'@ | ConvertFrom-Csv",
            "",
            "$installed = @{}",
            "Get-CimInstance -ClassName Win32_QuickFixEngineering | ForEach-Object {",
            "    if ($_.HotFixID) { $installed[$_.HotFixID.ToUpperInvariant()] = $true }",
            "}",
            "Get-HotFix | ForEach-Object {",
            "    if ($_.HotFixID) { $installed[$_.HotFixID.ToUpperInvariant()] = $true }",
            "}",
            "",
            "foreach ($item in $catalog) {",
            "    $kb = $item.KB.ToUpperInvariant()",
            "    [pscustomobject]@{",
            "        Computer   = $env:COMPUTERNAME",
            "        CVE        = $item.CVE",
            "        KB         = $kb",
            "        Product    = $item.Product",
            "        FixedBuild = $item.FixedBuild",
            "        Status     = $(if ($installed.ContainsKey($kb)) { 'Installed' } else { 'Not installed' })",
            "    }",
            "}",
            "",
        ]
    )
    script = "\n".join(lines)
    violations = remediation_violations(_executable_text(script))
    if violations:
        raise RuntimeError(f"Refusing to emit a script that contains {', '.join(violations)}")
    return script
