"""What-if: drop selected open findings and recompute the ops numbers.

Patched rows are removed from the open backlog. They are not written back
as fixes inside the last four weeks, so the close rate stays the rate the
team has already demonstrated. The forecast sentence remains a projection.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

import pandas as pd

from kev_radar.metrics import breach_forecast, is_open
from kev_radar.msrc import normalize_kb
from kev_radar.overview import portfolio_risk


@dataclass(frozen=True)
class WhatIf:
    patched: int
    cves: tuple[str, ...]
    hosts: int
    before_overdue: int
    after_overdue: int
    before_due: int
    after_due: int
    before_risk: float
    after_risk: float
    before_misses: int
    after_misses: int
    before_statement: str
    after_statement: str

    @property
    def overdue_delta(self) -> int:
        return self.before_overdue - self.after_overdue

    @property
    def risk_delta(self) -> float:
        return round(self.before_risk - self.after_risk, 1)


def cves_addressed_by_kb(snapshot: dict, kb: str) -> list[str]:
    """CVE IDs in the MSRC snapshot that list this KB as a vendor fix."""
    wanted = normalize_kb(kb)
    if not wanted:
        return []
    found: list[str] = []
    for cve, entry in (snapshot.get("cves") or {}).items():
        for patch in (entry or {}).get("patches") or []:
            if normalize_kb(patch.get("kb")) == wanted:
                found.append(str(cve).upper())
                break
    return sorted(set(found))


def _key(host: object, cve: object) -> tuple[str, str]:
    return (str(host).strip().lower(), str(cve).strip().upper())


def select_open_keys(
    findings: pd.DataFrame,
    *,
    cves: list[str] | None = None,
    hosts: list[str] | None = None,
    pairs: list[tuple[str, str]] | None = None,
) -> set[tuple[str, str]]:
    """Open findings matched by CVE, host, or an exact host+CVE pair.

    A CVE match patches every open instance of that CVE. A host match patches
    every open finding on that host. Pairs are exact.
    """
    if findings.empty:
        return set()
    open_rows = findings[findings["state"].map(is_open)]
    wanted_cves = {str(cve).upper() for cve in (cves or []) if str(cve).strip()}
    wanted_hosts = {str(host).strip().lower() for host in (hosts or []) if str(host).strip()}
    wanted_pairs = {_key(host, cve) for host, cve in (pairs or [])}
    chosen: set[tuple[str, str]] = set()
    for row in open_rows.itertuples(index=False):
        key = _key(row.host_name, row.cve)
        if key in wanted_pairs or key[1] in wanted_cves or key[0] in wanted_hosts:
            chosen.add(key)
    return chosen


def simulate(findings: pd.DataFrame, as_of: date, keys: set[tuple[str, str]]) -> WhatIf:
    """Compare overdue, risk, and the 7-day forecast with ``keys`` removed."""
    before = breach_forecast(findings, as_of)
    before_risk = portfolio_risk(findings)
    if findings.empty or not keys:
        after = before
        remaining = findings
    else:
        mask = [
            _key(host, cve) not in keys
            for host, cve in zip(findings["host_name"], findings["cve"], strict=True)
        ]
        remaining = findings[mask].reset_index(drop=True)
        after = breach_forecast(remaining, as_of)
    cves = tuple(sorted({cve for _, cve in keys}))
    hosts = len({host for host, _ in keys})
    return WhatIf(
        patched=len(keys),
        cves=cves,
        hosts=hosts,
        before_overdue=int(before.already_overdue),
        after_overdue=int(after.already_overdue),
        before_due=int(before.due_in_window),
        after_due=int(after.due_in_window),
        before_risk=before_risk,
        after_risk=portfolio_risk(remaining),
        before_misses=int(before.projected_misses),
        after_misses=int(after.projected_misses),
        before_statement=before.statement,
        after_statement=after.statement,
    )
