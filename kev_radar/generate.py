"""Build a synthetic Tenable Vulnerability Management findings export.

Hosts, owners, and addresses are fictional. CVE IDs are real public identifiers
drawn from a snapshot of CISA KEV and other published CVEs. Nothing here is an
employer export.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import date, timedelta
from io import StringIO
from random import Random

import pandas as pd

DEMO_SEED = 2604
DEFAULT_HOSTS = 300

BUSINESS_UNITS = [
    ("Payments", "pay", ("Priya Shah", "Luis Ortega")),
    ("Member Portal", "portal", ("Amira Haddad", "Jonah Reid")),
    ("Claims", "claims", ("Noah Berger", "Hannah Brooks")),
    ("Identity", "id", ("Marcus Chen", "Elena Voss")),
    ("Corporate IT", "corp", ("Sofia Almeida", "Hannah Brooks")),
    ("Edge Network", "edge", ("Owen Park", "Jonah Reid")),
]

# family, role, operating system, system type, count, business units
HOST_PLAN = [
    ("windows", "srv", "Microsoft Windows Server 2022", "server", 70, ("Corporate IT", "Claims", "Payments")),
    ("windows", "srv", "Microsoft Windows Server 2019", "server", 30, ("Identity", "Corporate IT")),
    ("workstation", "ws", "Microsoft Windows 11 Enterprise", "workstation", 70, ("Payments", "Claims", "Member Portal", "Corporate IT")),
    ("linux", "lnx", "Ubuntu 24.04 LTS", "server", 35, ("Member Portal", "Payments")),
    ("linux", "lnx", "Red Hat Enterprise Linux 9", "server", 25, ("Identity", "Member Portal")),
    ("network", "fw", "PAN-OS 11.1", "network", 20, ("Edge Network",)),
    ("network", "fw", "FortiOS 7.4", "network", 18, ("Edge Network",)),
    ("network", "rtr", "Cisco IOS XE 17.12", "network", 12, ("Edge Network",)),
    ("cloud", "cld", "Ubuntu 24.04 LTS", "server", 20, ("Member Portal", "Identity")),
]

EXPOSURE_RATE = {
    "network": 0.62,
    "cloud": 0.35,
    "linux": 0.14,
    "windows": 0.08,
    "workstation": 0.03,
}

EXPORT_COLUMNS = [
    "definition.id",
    "definition.name",
    "definition.cve",
    "definition.cvss3.base_score",
    "definition.cvss3.base_vector",
    "definition.epss.score",
    "definition.family",
    "definition.synopsis",
    "definition.solution",
    "severity",
    "state",
    "first_observed",
    "last_seen",
    "last_fixed",
    "port",
    "protocol",
    "output",
    "asset.id",
    "asset.name",
    "asset.host_name",
    "asset.display_ipv4_address",
    "asset.operating_system",
    "asset.system_type",
    "asset.tags",
]


@dataclass(frozen=True)
class Host:
    asset_id: str
    asset_name: str
    host_name: str
    ip: str
    operating_system: str
    system_type: str
    family: str
    owner: str
    business_unit: str
    exposed: bool

    def accepts(self, cve_family: str) -> bool:
        if cve_family in {"", "any"}:
            return True
        if self.family == "cloud":
            return cve_family in {"linux", "windows", "any"}
        if self.family == "workstation":
            return cve_family in {"workstation", "windows"}
        return cve_family == self.family


def _bu_owners() -> dict[str, tuple[str, ...]]:
    return {name: owners for name, _slug, owners in BUSINESS_UNITS}


def _slug_for(name: str) -> str:
    for full, slug, _owners in BUSINESS_UNITS:
        if full == name:
            return slug
    return "lab"


def build_hosts(rng: Random, count: int = DEFAULT_HOSTS) -> list[Host]:
    """Create fictional hosts. Addresses stay in RFC1918 or documentation space."""
    owners = _bu_owners()
    planned: list[tuple] = []
    for family, role, operating_system, system_type, planned_count, units in HOST_PLAN:
        for _ in range(planned_count):
            planned.append((family, role, operating_system, system_type, units))
    if count < len(planned):
        planned = planned[:count]
    elif count > len(planned):
        extra = count - len(planned)
        planned.extend([planned[index % len(planned)] for index in range(extra)])
    rng.shuffle(planned)

    hosts: list[Host] = []
    internal_n = 1
    exposed_n = 1
    serial = {key: 0 for key in {item[1] for item in planned}}
    for family, role, operating_system, system_type, units in planned:
        business_unit = rng.choice(units)
        owner = rng.choice(owners[business_unit])
        serial[role] += 1
        asset_name = f"hl-{_slug_for(business_unit)}-{role}-{serial[role]:03d}"
        host_name = f"{asset_name}.lab.invalid"
        exposed = rng.random() < EXPOSURE_RATE[family]
        if exposed:
            ip = f"203.0.113.{((exposed_n - 1) % 250) + 1}"
            exposed_n += 1
        else:
            ip = f"10.{(internal_n // 200) + 8}.{(internal_n // 10) % 20}.{(internal_n % 10) + 10}"
            internal_n += 1
        hosts.append(
            Host(
                asset_id=str(uuid.uuid5(uuid.NAMESPACE_DNS, host_name)),
                asset_name=asset_name,
                host_name=host_name,
                ip=ip,
                operating_system=operating_system,
                system_type=system_type,
                family=family,
                owner=owner,
                business_unit=business_unit,
                exposed=exposed,
            )
        )
    return hosts


def _iso(day: date) -> str:
    return f"{day.isoformat()}T15:04:00Z"


def _parse_added(value: object) -> date | None:
    if value is None or str(value).strip() == "":
        return None
    text = str(value).strip()[:10]
    try:
        year, month, day = (int(part) for part in text.split("-"))
        return date(year, month, day)
    except ValueError:
        return None


def _is_this_week(entry: dict, as_of: date) -> bool:
    added = _parse_added(entry.get("date_added"))
    if added is None or not entry.get("in_kev"):
        return False
    return as_of - timedelta(days=6) <= added <= as_of


def _severity(cvss: float | None, in_kev: bool) -> str:
    if cvss is None:
        return "high" if in_kev else "medium"
    if cvss >= 9:
        return "critical"
    if cvss >= 7:
        return "high"
    if cvss >= 4:
        return "medium"
    if cvss > 0:
        return "low"
    return "info"


def _kev_age_days(entry: dict, as_of: date) -> int | None:
    added = _parse_added(entry.get("date_added"))
    if added is None:
        return None
    return (as_of - added).days


def _age_days(rng: Random, entry: dict, this_week: bool, as_of: date) -> int:
    """Age the finding so deadlines land both inside and outside the window.

    Old KEV listings are already past a 3- or 14-day clock no matter when the
    scanner first saw them, so those stay in the overdue backlog. Non-KEV
    findings and this week's KEV entries carry the on-track and due-soon work.
    """
    if this_week:
        return rng.choice((0, 1, 2, 3, 5, 9, 16))
    if not entry.get("in_kev"):
        roll = rng.random()
        if roll < 0.34:
            return rng.randint(0, 10)
        if roll < 0.58:
            return rng.randint(11, 20)
        if roll < 0.82:
            return rng.randint(21, 50)
        return rng.randint(51, 75)
    kev_age = _kev_age_days(entry, as_of)
    if kev_age is not None and kev_age <= 21:
        return rng.randint(0, max(1, min(12, kev_age)))
    return rng.randint(15, 80)


def _should_fix(rng: Random, entry: dict, this_week: bool, as_of: date) -> bool:
    if this_week:
        return False
    kev_age = _kev_age_days(entry, as_of)
    if entry.get("in_kev") and kev_age is not None and kev_age > 45:
        return rng.random() < 0.84
    return rng.random() < 0.28


def _matching(hosts: list[Host], family: str) -> list[Host]:
    matched = [host for host in hosts if host.accepts(family)]
    return matched or list(hosts)


PLUGIN_FAMILY = {
    "windows": "Windows",
    "linux": "General",
    "network": "Firewalls",
    "workstation": "Windows",
    "cloud": "General",
}


def export_row(
    host: Host,
    entry: dict,
    *,
    plugin: int,
    state: str,
    first: date,
    last_seen: date,
    last_fixed: date | None,
) -> dict:
    """One Tenable-shaped export row for a host and a pool entry. Shared with evolve.py."""
    cve = str(entry["cve"]).upper()
    cvss = entry.get("cvss")
    try:
        cvss_value = float(cvss) if cvss is not None and str(cvss) != "" else None
    except (TypeError, ValueError):
        cvss_value = None
    name = str(entry.get("name") or cve)
    family = str(entry.get("family") or "any")
    epss = entry.get("epss")
    tags = json.dumps(
        {
            "Owner": [host.owner],
            "Business Unit": [host.business_unit],
            "Internet Exposed": ["Yes" if host.exposed else "No"],
            "Environment": ["Synthetic lab"],
        },
        separators=(",", ":"),
    )
    return {
        "definition.id": str(plugin),
        "definition.name": name,
        "definition.cve": cve,
        "definition.cvss3.base_score": "" if cvss_value is None else f"{cvss_value:.1f}",
        "definition.cvss3.base_vector": entry.get("cvss_vector") or "",
        "definition.epss.score": "" if epss in (None, "") else f"{float(epss):.5f}",
        "definition.family": PLUGIN_FAMILY.get(family, "Misc."),
        "definition.synopsis": f"Synthetic check for {name}.",
        "definition.solution": (
            "Apply the vendor fix and rescan. Synthetic guidance for the Harborline Mutual lab, "
            "not an instruction for a production system."
        ),
        "severity": _severity(cvss_value, bool(entry.get("in_kev"))),
        "state": state,
        "first_observed": _iso(first),
        "last_seen": _iso(last_seen),
        "last_fixed": _iso(last_fixed) if last_fixed else "",
        "port": "443",
        "protocol": "tcp",
        "output": (
            f"Synthetic plugin output. {host.host_name} matched {cve}. "
            "This row is synthetic demo data, not a real scan."
        ),
        "asset.id": host.asset_id,
        "asset.name": host.asset_name,
        "asset.host_name": host.host_name,
        "asset.display_ipv4_address": host.ip,
        "asset.operating_system": host.operating_system,
        "asset.system_type": host.system_type,
        "asset.tags": tags,
    }


def generate_frame(
    pool: list[dict],
    *,
    as_of: date | None = None,
    seed: int = DEMO_SEED,
    host_count: int = DEFAULT_HOSTS,
) -> pd.DataFrame:
    """Return a Tenable-shaped findings frame. ``pool`` entries need a ``cve`` key."""
    if not pool:
        raise ValueError("CVE pool is empty. Refresh the public snapshots first.")
    as_of = as_of or date.today()
    rng = Random(seed)
    hosts = build_hosts(rng, host_count)
    week = [entry for entry in pool if _is_this_week(entry, as_of)]
    rest = [entry for entry in pool if entry not in week]
    non_kev = [entry for entry in rest if not entry.get("in_kev")]
    recent_kev = [
        entry
        for entry in rest
        if entry.get("in_kev") and (_kev_age_days(entry, as_of) or 999) <= 45
    ]
    older = [entry for entry in rest if entry not in non_kev and entry not in recent_kev]
    assigned: set[tuple[str, str]] = set()
    pairs: list[tuple[Host, dict, bool]] = []

    for entry in week:
        matching = _matching(hosts, str(entry.get("family") or "any"))
        exposed = [host for host in matching if host.exposed]
        internal = [host for host in matching if not host.exposed]
        chosen: list[Host] = []
        if exposed:
            chosen.append(rng.choice(exposed))
        if internal:
            chosen.append(rng.choice(internal))
        extras = rng.sample(matching, k=min(rng.randint(1, 3), len(matching)))
        for host in extras:
            if host not in chosen:
                chosen.append(host)
        for host in chosen:
            key = (host.asset_id, entry["cve"])
            if key in assigned:
                continue
            assigned.add(key)
            pairs.append((host, entry, True))

    def _pick(options: list[dict], host: Host) -> dict | None:
        if not options:
            return None
        matching = [entry for entry in options if host.accepts(str(entry.get("family") or "any"))]
        return rng.choice(matching or options)

    for host in hosts:
        chosen: list[dict] = []
        for bucket in (non_kev, recent_kev):
            picked = _pick(bucket, host)
            if picked is not None:
                chosen.append(picked)
        extra_source = older or rest or list(pool)
        matching = [entry for entry in extra_source if host.accepts(str(entry.get("family") or "any"))]
        take = min(len(matching or extra_source), rng.randint(1, 3))
        chosen.extend(rng.sample(matching or extra_source, k=take))
        for entry in chosen:
            key = (host.asset_id, entry["cve"])
            if key in assigned:
                continue
            assigned.add(key)
            pairs.append((host, entry, False))

    rows: list[dict] = []
    plugin = 9_000_000
    for host, entry, this_week in pairs:
        plugin += 1
        age = _age_days(rng, entry, this_week, as_of)
        first = as_of - timedelta(days=age)
        fixed: date | None = None
        if not _should_fix(rng, entry, this_week, as_of):
            state = "REOPENED" if (not this_week and rng.random() < 0.08) else "OPEN"
            last_seen = as_of - timedelta(days=rng.randint(0, 2))
        else:
            state = "FIXED"
            kev_age = _kev_age_days(entry, as_of)
            if entry.get("in_kev") and kev_age is not None and kev_age > 45:
                # Closed earlier, so the recent close rate is not dominated by old backlog.
                age = rng.randint(55, 120)
                first = as_of - timedelta(days=age)
                fixed = first + timedelta(days=rng.randint(4, 20))
                if fixed > as_of - timedelta(days=29):
                    fixed = as_of - timedelta(days=rng.randint(29, 55))
                if fixed < first:
                    fixed = first
            else:
                fixed = first + timedelta(days=rng.randint(3, 24))
                if fixed > as_of:
                    fixed = as_of
            last_seen = fixed
        base = export_row(host, entry, plugin=plugin, state=state, first=first, last_seen=last_seen, last_fixed=fixed)
        rows.append(base)
        if rng.random() < 0.12:
            duplicate = dict(base)
            duplicate["port"] = "8443"
            duplicate["definition.id"] = str(plugin + 50_000)
            later = min(as_of, first + timedelta(days=1))
            duplicate["first_observed"] = _iso(later)
            duplicate["output"] = (
                f"Synthetic plugin output, second port. {host.host_name} matched {base['definition.cve']} on 8443."
            )
            rows.append(duplicate)

    frame = pd.DataFrame(rows, columns=EXPORT_COLUMNS)
    return frame


def generate_csv(
    pool: list[dict],
    *,
    as_of: date | None = None,
    seed: int = DEMO_SEED,
    host_count: int = DEFAULT_HOSTS,
) -> str:
    frame = generate_frame(pool, as_of=as_of, seed=seed, host_count=host_count)
    buffer = StringIO()
    frame.to_csv(buffer, index=False, lineterminator="\n")
    return buffer.getvalue()
