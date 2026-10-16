"""Display helpers that do not import Streamlit."""

from __future__ import annotations

import pandas as pd

from kev_radar.metrics import is_open

QUEUE_COLUMNS = [
    "band",
    "score",
    "host_name",
    "owner",
    "business_unit",
    "cve",
    "vuln_name",
    "exposed",
    "epss",
    "cvss",
    "deadline",
    "days_left",
    "sla_status",
    "decision_path",
]

CLASSIC_COLUMNS = [
    "band",
    "score",
    "host_name",
    "owner",
    "business_unit",
    "cve",
    "vuln_name",
    "ssvc_decision",
    "ssvc_path",
    "decision_path",
]


def format_days(value: object, sla_status: object) -> str:
    if sla_status == "Upgrade cycle":
        return "Upgrade cycle"
    if sla_status == "Exception":
        return "Paused"
    if value is None:
        return "—"
    try:
        if pd.isna(value):
            return "—"
    except TypeError:
        pass
    days = int(value)
    if days < 0:
        return f"{abs(days)}d overdue"
    if days == 0:
        return "Due today"
    return f"{days}d left"


def queue_frame(findings: pd.DataFrame, *, classic: bool) -> pd.DataFrame:
    if findings.empty:
        columns = CLASSIC_COLUMNS if classic else QUEUE_COLUMNS
        return pd.DataFrame(columns=columns)
    frame = findings.copy()
    frame["exposed"] = frame["exposed"].map(lambda flag: "Yes" if bool(flag) else "No")
    frame["deadline"] = frame["deadline"].map(lambda value: "—" if value is None or pd.isna(value) else str(value)[:10])
    if classic:
        return frame[CLASSIC_COLUMNS]
    frame["days_left_label"] = [
        format_days(days, sla) for days, sla in zip(frame["days_left"], frame["sla_status"], strict=True)
    ]
    shown = frame[QUEUE_COLUMNS].copy()
    shown["days_left"] = frame["days_left_label"]
    return shown


def csv_download(findings: pd.DataFrame) -> str:
    if findings.empty:
        return ""
    export = findings.copy()
    for column in export.columns:
        export[column] = export[column].map(lambda value: "" if value is None else value)
    return export.to_csv(index=False)


def scatter_frame(findings: pd.DataFrame) -> pd.DataFrame:
    if findings.empty:
        return pd.DataFrame(columns=["cve", "cvss", "epss", "hosts", "kev", "name"])
    grouped = (
        findings.groupby("cve", dropna=False)
        .agg(
            cvss=("cvss", "max"),
            epss=("epss", "max"),
            hosts=("host_name", "nunique"),
            in_kev=("in_kev", "max"),
            name=("vuln_name", "first"),
        )
        .reset_index()
    )
    grouped = grouped.dropna(subset=["cvss", "epss"])
    grouped["kev"] = grouped["in_kev"].map(lambda flag: "In KEV" if bool(flag) else "Not in KEV")
    grouped["epss_percent"] = grouped["epss"] * 100
    return grouped


def vendor_frame(findings: pd.DataFrame) -> pd.DataFrame:
    if findings.empty:
        return pd.DataFrame(columns=["vendor", "findings"])
    open_kev = findings[findings["in_kev"].map(bool) & findings["state"].map(is_open)]
    if open_kev.empty:
        return pd.DataFrame(columns=["vendor", "findings"])
    counts = (
        open_kev.groupby(open_kev["kev_vendor"].fillna("Unknown"))
        .size()
        .reset_index(name="findings")
        .rename(columns={"kev_vendor": "vendor"})
        .sort_values("findings", ascending=False)
        .head(8)
    )
    return counts.reset_index(drop=True)


def kev_additions_by_month(vulnerabilities: list[dict], months: int = 18) -> pd.DataFrame:
    dates = []
    for entry in vulnerabilities:
        added = str(entry.get("dateAdded") or "")[:7]
        if len(added) == 7:
            dates.append(added)
    if not dates:
        return pd.DataFrame(columns=["month", "additions"])
    frame = pd.Series(dates).value_counts().rename_axis("month").reset_index(name="additions")
    frame = frame.sort_values("month")
    if len(frame) > months:
        frame = frame.tail(months)
    return frame.reset_index(drop=True)
