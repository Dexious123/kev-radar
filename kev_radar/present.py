"""Display helpers that do not import Streamlit."""

from __future__ import annotations

from urllib.parse import urlencode

import pandas as pd

from kev_radar.metrics import is_open
from kev_radar.textsafe import spreadsheet_cell

LAB_DOMAIN = ".lab.invalid"

# Display names for the queue's columns; the frame keeps its own names for exports.
QUEUE_LABELS = {
    "band": "Band",
    "score": "Score",
    "host_name": "Host",
    "owner": "Owner",
    "business_unit": "Business unit",
    "cve": "CVE",
    "vuln_name": "Vulnerability",
    "exposed": "Exposed",
    "epss": "EPSS",
    "cvss": "CVSS",
    "deadline": "Deadline",
    "days_left": "Time left",
    "sla_status": "Status",
    "decision_path": "Decision path",
    "ssvc_decision": "SSVC decision",
    "ssvc_path": "SSVC path",
}


def short_host(name: object) -> str:
    """The lab's hosts all end in the reserved .lab.invalid domain, so the suffix carries no information."""
    text = str(name or "")
    return text[: -len(LAB_DOMAIN)] if text.endswith(LAB_DOMAIN) else text


def queue_link(host: object, cve: object) -> str:
    """A link that opens the fix queue on one finding. Values are URL-encoded; escape it again for HTML."""
    return "?" + urlencode({"page": "Fix queue", "finding": f"{host}|{cve}"})


def find_in_queue(queue: pd.DataFrame, requested: object) -> int | None:
    """Row position of a ``host|cve`` finding in the queue, or None."""
    host, sep, cve = str(requested or "").partition("|")
    if not sep or queue.empty:
        return None
    hits = queue.index[(queue["host_name"].astype(str) == host) & (queue["cve"].astype(str).str.upper() == cve.upper())]
    return int(queue.index.get_loc(hits[0])) if len(hits) else None

QUEUE_COLUMNS = [
    "band",
    "score",
    "cve",
    "vuln_name",
    "host_name",
    "owner",
    "business_unit",
    "sla_status",
    "days_left",
    "deadline",
    "exposed",
    "epss",
    "cvss",
    "decision_path",
]

CLASSIC_COLUMNS = [
    "band",
    "score",
    "cve",
    "vuln_name",
    "host_name",
    "owner",
    "business_unit",
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
        export[column] = export[column].map(lambda value: "" if value is None else spreadsheet_cell(value))
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
