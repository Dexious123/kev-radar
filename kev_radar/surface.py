"""Attack-surface rollups: exposure × KEV × EPSS by business unit, and a host."""

from __future__ import annotations

import pandas as pd

from kev_radar.metrics import is_open

LANES = (
    "Internal · not KEV",
    "Internal · KEV",
    "Exposed · not KEV",
    "Exposed · KEV",
)


def _lane(exposed: bool, in_kev: bool) -> str:
    if exposed and in_kev:
        return LANES[3]
    if exposed:
        return LANES[2]
    if in_kev:
        return LANES[1]
    return LANES[0]


def exposure_heatmap(findings: pd.DataFrame) -> pd.DataFrame:
    """One row per business unit and lane, for open findings only.

    ``mean_epss`` is None when no row in the cell has an EPSS score. The
    color scale should treat that as empty, not as zero probability.
    """
    columns = ["business_unit", "lane", "findings", "kev", "mean_epss"]
    if findings.empty:
        return pd.DataFrame(columns=columns)
    open_rows = findings[findings["state"].map(is_open)].copy()
    if open_rows.empty:
        return pd.DataFrame(columns=columns)
    open_rows["lane"] = [
        _lane(bool(exposed), bool(in_kev))
        for exposed, in_kev in zip(open_rows["exposed"], open_rows["in_kev"], strict=True)
    ]
    open_rows["business_unit"] = open_rows["business_unit"].fillna("Unassigned").replace("", "Unassigned")
    grouped = (
        open_rows.groupby(["business_unit", "lane"], dropna=False)
        .agg(
            findings=("cve", "size"),
            kev=("in_kev", "sum"),
            mean_epss=("epss", "mean"),
        )
        .reset_index()
    )
    grouped["kev"] = grouped["kev"].astype(int)
    grouped["mean_epss"] = grouped["mean_epss"].round(3)
    return grouped.sort_values(["business_unit", "lane"]).reset_index(drop=True)


def heatmap_matrix(summary: pd.DataFrame) -> tuple[list[str], list[str], list[list[float | None]], list[list[str]]]:
    """Pivot the summary into Plotly heatmap inputs.

    Color is mean EPSS. Cell text is the open-finding count.
    """
    if summary.empty:
        return [], list(LANES), [], []
    units = sorted(summary["business_unit"].unique())
    z: list[list[float | None]] = []
    text: list[list[str]] = []
    lookup = {
        (row.business_unit, row.lane): row
        for row in summary.itertuples(index=False)
    }
    for unit in units:
        z_row: list[float | None] = []
        t_row: list[str] = []
        for lane in LANES:
            cell = lookup.get((unit, lane))
            if cell is None:
                z_row.append(None)
                t_row.append("0")
            else:
                epss = cell.mean_epss
                z_row.append(None if pd.isna(epss) else float(epss))
                t_row.append(str(int(cell.findings)))
        z.append(z_row)
        text.append(t_row)
    return units, list(LANES), z, text


def host_index(findings: pd.DataFrame) -> pd.DataFrame:
    """One row per host, worst open score first."""
    columns = ["host_name", "owner", "business_unit", "exposed", "open_findings", "overdue", "max_score"]
    if findings.empty:
        return pd.DataFrame(columns=columns)
    rows = []
    for host, group in findings.groupby("host_name", dropna=False):
        open_rows = group[group["state"].map(is_open)]
        first = group.iloc[0]
        overdue = 0
        if not open_rows.empty and "sla_status" in open_rows.columns:
            overdue = int((open_rows["sla_status"] == "Overdue").sum())
        max_score = 0.0
        if not open_rows.empty:
            max_score = round(float(open_rows["score"].fillna(0).max()), 1)
        rows.append(
            {
                "host_name": host,
                "owner": first.get("owner") or "Unassigned",
                "business_unit": first.get("business_unit") or "Unassigned",
                "exposed": bool(first.get("exposed")),
                "open_findings": int(len(open_rows)),
                "overdue": overdue,
                "max_score": max_score,
            }
        )
    frame = pd.DataFrame(rows, columns=columns)
    return frame.sort_values(
        ["open_findings", "max_score", "host_name"],
        ascending=[False, False, True],
    ).reset_index(drop=True)


def host_findings(findings: pd.DataFrame, host_name: str) -> pd.DataFrame:
    """Every finding on one host, open rows first."""
    if findings.empty:
        return findings.copy()
    rows = findings[findings["host_name"] == host_name].copy()
    if rows.empty:
        return rows
    rows["_open"] = rows["state"].map(lambda value: 0 if is_open(value) else 1)
    return rows.sort_values(["_open", "score"], ascending=[True, False]).drop(columns=["_open"]).reset_index(drop=True)
