"""Advance the Harborline Mutual estate one day at a time.

The bundled estate used to be rebuilt from scratch every morning, so nothing that
happened yesterday was remembered and the trend charts were re-invented daily. This
module keeps it continuous. Each simulated day:

- the scanner rescans, so every open finding is seen again;
- KEV entries that CISA added in the last three days land on matching hosts;
- the scanner discovers a few new non-KEV findings from the current pool;
- owners close findings at a weekday pace, newest KEVs and exposed hosts first;
- now and then a recent fix regresses and the finding reopens;
- fixed rows older than the retention window drop out of the export.

Every random choice is seeded by the date, so replaying a day gives the same result
and missed days can be caught up one at a time. The estate and its daily work are
simulated; the CVE IDs, the KEV catalog, and the EPSS scores are real public data.
"""

from __future__ import annotations

import json
from datetime import date, timedelta
from io import StringIO
from pathlib import Path
from random import Random

import pandas as pd

from kev_radar.generate import DEMO_SEED, EXPORT_COLUMNS, Host, _iso, _matching, _parse_added, export_row

OPEN_STATES = {"OPEN", "REOPENED"}
NEW_KEV_WINDOW_DAYS = 3
RETENTION_DAYS = 180
LOG_DAYS = 30
MAX_CATCH_UP_DAYS = 31

ROLE_FAMILY = {"srv": "windows", "ws": "workstation", "lnx": "linux", "fw": "network", "rtr": "network", "cld": "cloud"}
SEVERITY_WEIGHT = {"critical": 2.0, "high": 1.5}
KEV_WEIGHT = 3.0
# A KEV entry the team saw in the last two weeks is the work it drops everything for.
FRESH_KEV_WEIGHT = 10.0
# Inflow (new non-KEV findings, plus about three hosts per new KEV entry) and the weekday
# close pace are balanced near the starting estate's 22 closes a week, so it neither drains
# nor grows without bound.
DISCOVERIES = (0, 1, 1, 2, 2, 3)
WEEKDAY_CLOSES = (3, 6)
# Above this many open host-and-CVE findings, owners close one more each weekday.
BACKLOG_PRESSURE = 600


def read_estate(text: str) -> pd.DataFrame:
    return pd.read_csv(StringIO(text), dtype=str, keep_default_na=False)


def write_estate(frame: pd.DataFrame) -> str:
    buffer = StringIO()
    frame[EXPORT_COLUMNS].to_csv(buffer, index=False, lineterminator="\n")
    return buffer.getvalue()


def _day_of(stamp: str) -> date | None:
    return _parse_added(stamp)


def hosts_from_estate(frame: pd.DataFrame) -> list[Host]:
    """Rebuild the host list from the export itself, so the estate needs no side file."""
    hosts: dict[str, Host] = {}
    for row in frame.drop_duplicates("asset.id").to_dict("records"):
        try:
            tags = json.loads(row["asset.tags"])
        except (TypeError, ValueError):
            tags = {}
        role = (row["asset.name"].split("-") + ["", "", ""])[2]
        hosts[row["asset.id"]] = Host(
            asset_id=row["asset.id"],
            asset_name=row["asset.name"],
            host_name=row["asset.host_name"],
            ip=row["asset.display_ipv4_address"],
            operating_system=row["asset.operating_system"],
            system_type=row["asset.system_type"],
            family=ROLE_FAMILY.get(role, "cloud"),
            owner=(tags.get("Owner") or ["Unassigned"])[0],
            business_unit=(tags.get("Business Unit") or ["Unassigned"])[0],
            exposed=(tags.get("Internet Exposed") or ["No"])[0] == "Yes",
        )
    return sorted(hosts.values(), key=lambda host: host.asset_id)


def _new_rows(
    frame: pd.DataFrame, pairs: list[tuple[Host, dict]], day: date, next_plugin: int
) -> tuple[pd.DataFrame, int]:
    rows = []
    for host, entry in pairs:
        rows.append(export_row(host, entry, plugin=next_plugin, state="OPEN", first=day, last_seen=day, last_fixed=None))
        next_plugin += 1
    if not rows:
        return frame, next_plugin
    return pd.concat([frame, pd.DataFrame(rows, columns=EXPORT_COLUMNS)], ignore_index=True), next_plugin


def _weight(row: dict, entry: dict | None, day: date) -> float:
    weight = SEVERITY_WEIGHT.get(str(row.get("severity", "")).lower(), 1.0)
    try:
        exposed = json.loads(row["asset.tags"]).get("Internet Exposed", ["No"])[0] == "Yes"
    except (TypeError, ValueError):
        exposed = False
    if exposed:
        weight *= 2.0
    if entry and entry.get("in_kev"):
        weight *= KEV_WEIGHT
        first = _day_of(row["first_observed"])
        if first and (day - first).days <= 14:
            weight *= FRESH_KEV_WEIGHT
    return weight


def advance_one_day(frame: pd.DataFrame, pool: list[dict], day: date, *, seed: int = DEMO_SEED) -> tuple[pd.DataFrame, dict]:
    rng = Random(f"{seed}:{day.isoformat()}")
    frame = frame.copy()
    frame["state"] = frame["state"].str.upper()
    by_cve = {str(entry["cve"]).upper(): entry for entry in pool}
    hosts = hosts_from_estate(frame)
    host_by_id = {host.asset_id: host for host in hosts}
    events: dict = {"date": day.isoformat(), "fixed": [], "new_kev": [], "discovered": [], "reopened": []}
    stamp = _iso(day)
    ids = pd.to_numeric(frame["definition.id"], errors="coerce")
    next_plugin = int(ids.max()) + 1 if ids.notna().any() else 9_000_001

    # 1. The scanner sees every open finding again.
    frame.loc[frame["state"].isin(OPEN_STATES), "last_seen"] = stamp

    # 2. KEV entries CISA added in the last few days land on matching hosts.
    present = set(frame["definition.cve"].str.upper())
    fresh = []
    for cve, entry in sorted(by_cve.items()):
        added = _parse_added(entry.get("date_added"))
        if entry.get("in_kev") and added and day - timedelta(days=NEW_KEV_WINDOW_DAYS - 1) <= added <= day and cve not in present:
            fresh.append(entry)
    pairs: list[tuple[Host, dict]] = []
    for entry in fresh:
        matching = _matching(hosts, str(entry.get("family") or "any"))
        exposed = [host for host in matching if host.exposed]
        internal = [host for host in matching if not host.exposed]
        chosen = []
        if exposed:
            chosen.append(rng.choice(exposed))
        if internal:
            chosen.append(rng.choice(internal))
        for host in rng.sample(matching, k=min(rng.randint(0, 2), len(matching))):
            if host not in chosen:
                chosen.append(host)
        pairs.extend((host, entry) for host in chosen)
        events["new_kev"].append(
            {
                "cve": str(entry["cve"]).upper(),
                "name": str(entry.get("name") or ""),
                "vendor": str(entry.get("vendor") or ""),
                "product": str(entry.get("product") or ""),
                "hosts": [host.host_name for host in chosen],
            }
        )
    frame, next_plugin = _new_rows(frame, pairs, day, next_plugin)

    # 3. The scanner finds a few non-KEV CVEs on hosts that never had them.
    have = set(zip(frame["asset.id"], frame["definition.cve"].str.upper(), strict=True))
    non_kev = [entry for _cve, entry in sorted(by_cve.items()) if not entry.get("in_kev")]
    discovered: list[tuple[Host, dict]] = []
    for _ in range(rng.choice(DISCOVERIES) if non_kev else 0):
        entry = rng.choice(non_kev)
        cve = str(entry["cve"]).upper()
        options = [host for host in _matching(hosts, str(entry.get("family") or "any")) if (host.asset_id, cve) not in have]
        if not options:
            continue
        host = rng.choice(options)
        have.add((host.asset_id, cve))
        discovered.append((host, entry))
        events["discovered"].append({"cve": cve, "host": host.host_name})
    frame, next_plugin = _new_rows(frame, discovered, day, next_plugin)

    # 4. Owners close findings: a weekday pace, almost nothing on weekends.
    capacity = rng.randint(*WEEKDAY_CLOSES) if day.weekday() < 5 else rng.choice((0, 0, 1))
    candidates: dict[tuple[str, str], float] = {}
    for row in frame[frame["state"].isin(OPEN_STATES)].to_dict("records"):
        if row["first_observed"] == stamp:
            continue
        key = (row["asset.id"], row["definition.cve"].upper())
        candidates[key] = max(candidates.get(key, 0.0), _weight(row, by_cve.get(key[1]), day))
    if day.weekday() < 5 and len(candidates) > BACKLOG_PRESSURE:
        capacity += 1
    keys = sorted(candidates)
    for _ in range(min(capacity, len(keys))):
        pick = rng.choices(keys, weights=[candidates[key] for key in keys], k=1)[0]
        keys.remove(pick)
        mask = (frame["asset.id"] == pick[0]) & (frame["definition.cve"].str.upper() == pick[1])
        frame.loc[mask, ["state", "last_fixed", "last_seen"]] = ["FIXED", stamp, stamp]
        host = host_by_id.get(pick[0])
        events["fixed"].append(
            {"cve": pick[1], "host": host.host_name if host else pick[0], "owner": host.owner if host else "Unassigned"}
        )

    # 5. Now and then a recent fix regresses.
    if rng.random() < 0.12:
        recent = frame[
            (frame["state"] == "FIXED")
            & frame["last_fixed"].map(lambda value: bool(_day_of(value)) and 1 <= (day - _day_of(value)).days <= 60)
        ]
        keys = sorted(set(zip(recent["asset.id"], recent["definition.cve"].str.upper(), strict=True)))
        if keys:
            pick = rng.choice(keys)
            mask = (frame["asset.id"] == pick[0]) & (frame["definition.cve"].str.upper() == pick[1])
            frame.loc[mask, ["state", "last_seen"]] = ["REOPENED", stamp]
            host = host_by_id.get(pick[0])
            events["reopened"].append({"cve": pick[1], "host": host.host_name if host else pick[0]})

    # 6. Fixed findings past the retention window leave the export.
    cutoff = day - timedelta(days=RETENTION_DAYS)
    stale = (frame["state"] == "FIXED") & frame["last_fixed"].map(lambda value: bool(_day_of(value)) and _day_of(value) < cutoff)
    frame = frame[~stale].reset_index(drop=True)
    return frame, events


def advance_to(
    frame: pd.DataFrame, pool: list[dict], since: date, until: date, *, seed: int = DEMO_SEED
) -> tuple[pd.DataFrame, list[dict]]:
    """Advance from the day after ``since`` through ``until``, one day at a time."""
    start = max(since + timedelta(days=1), until - timedelta(days=MAX_CATCH_UP_DAYS - 1))
    log: list[dict] = []
    day = start
    while day <= until:
        frame, events = advance_one_day(frame, pool, day, seed=seed)
        log.append(events)
        day += timedelta(days=1)
    return frame, log


def load_log(path: Path) -> dict | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict) or not _parse_added(payload.get("as_of")):
        return None
    return payload


def save_log(path: Path, as_of: date, days: list[dict], *, seed: int = DEMO_SEED) -> None:
    payload = {"seed": seed, "as_of": as_of.isoformat(), "days": days[-LOG_DAYS:]}
    path.write_text(json.dumps(payload, indent=1) + "\n", encoding="utf-8")


def _count(number: int, one: str, many: str) -> str:
    return f"{number} {one if number == 1 else many}"


QUIET_DAY = "nothing was fixed and the scanner found nothing new"


def join_clauses(clauses: list[str]) -> str:
    if len(clauses) <= 2:
        return " and ".join(clauses)
    return ", ".join(clauses[:-1]) + ", and " + clauses[-1]


def day_clauses(events: dict) -> list[str]:
    """What changed that day, as lowercase clauses; empty on a quiet day."""
    clauses = []
    fixed = len(events.get("fixed", []))
    if fixed:
        clauses.append(f"owners closed {_count(fixed, 'finding', 'findings')}")
    new_kev = events.get("new_kev", [])
    if len(new_kev) == 1:
        entry = new_kev[0]
        product = " ".join(part for part in (entry.get("vendor"), entry.get("product")) if part)
        label = f"{entry['cve']} ({product})" if product else entry["cve"]
        clauses.append(f"new KEV entry {label} turned up on {_count(len(entry['hosts']), 'host', 'hosts')}")
    elif new_kev:
        hosts = sum(len(entry["hosts"]) for entry in new_kev)
        clauses.append(f"{len(new_kev)} new KEV entries turned up on {_count(hosts, 'host', 'hosts')}")
    discovered = len(events.get("discovered", []))
    if discovered:
        other = "other " if new_kev else ""
        clauses.append(f"the scanner found {_count(discovered, f'{other}new issue', f'{other}new issues')}")
    reopened = len(events.get("reopened", []))
    if reopened:
        clauses.append(f"{_count(reopened, 'fixed finding', 'fixed findings')} came back")
    return clauses


def summarize_day(events: dict) -> str:
    """One plain sentence about what changed that day."""
    sentence = join_clauses(day_clauses(events)) or QUIET_DAY
    return sentence[0].upper() + sentence[1:] + "."
