"""Risk-acceptance exceptions that pause SLA breach counting.

An exception is active through its expiry date, including that date. An active
exception takes the finding out of the overdue count, the 7-day breach
projection, and the SLO population. The day after expiry the finding is
flagged Expired and the clock counts again.
"""

from __future__ import annotations

import csv
import json
import os
from dataclasses import dataclass
from datetime import date, timedelta
from io import StringIO
from pathlib import Path

import pandas as pd

from kev_radar.metrics import is_open
from kev_radar.textsafe import from_spreadsheet_cell, spreadsheet_cell

OPERATOR_REGISTER = Path(__file__).resolve().parents[1] / "data" / "operator" / "exceptions.json"
OPERATOR_FILE_ENV = "KEV_RADAR_OPERATOR_FILE"
MAX_IMPORT_ROWS = 500


def operator_file_enabled(environ: dict | None = None) -> bool:
    """Whether the register is read from and written to ``OPERATOR_REGISTER``.

    Off by default. One server process serves every visitor, so a shared file
    would let one anonymous visitor change the exceptions, and the dashboard
    numbers, that every other visitor sees. Without the flag the register lives
    in each visitor's own session. Set the flag only on a single-user install.
    """
    value = (environ if environ is not None else os.environ).get(OPERATOR_FILE_ENV, "")
    return str(value).strip().lower() in {"1", "true", "yes"}


def enforce_import_limit(records: list) -> tuple[list, list[str]]:
    """Refuse an import larger than ``MAX_IMPORT_ROWS`` instead of loading part of it."""
    if len(records) > MAX_IMPORT_ROWS:
        return [], [f"That file has {len(records)} exceptions. The import limit is {MAX_IMPORT_ROWS}, so nothing was imported."]
    return records, []

_EXPORT_FIELDS = (
    "exception_id",
    "host_name",
    "cve",
    "owner",
    "justification",
    "compensating_controls",
    "expiry",
    "approver",
)

_HEADER_ALIASES = {
    "id": "exception_id",
    "exception id": "exception_id",
    "exception_id": "exception_id",
    "host": "host_name",
    "host_name": "host_name",
    "hostname": "host_name",
    "cve": "cve",
    "owner": "owner",
    "justification": "justification",
    "compensating controls": "compensating_controls",
    "compensating_controls": "compensating_controls",
    "expiry": "expiry",
    "expires": "expiry",
    "approver": "approver",
    "status": "_ignore",
    "expired": "_ignore",
    "in this filter": "_ignore",
}

APPROVERS = ("Morgan Ellis", "Rita Okonkwo", "Helen Cho")

_JUSTIFICATIONS = (
    "The vendor fix is queued for the next change window. Until then the vulnerable service is reachable only from the management network.",
    "The published exploit path is blocked at the edge firewall. The owner keeps the exception only for this host.",
    "Detection is in place for the known payload, and the asset stays in the reviewed change queue.",
)

_CONTROLS = (
    "Management VLAN only. The edge firewall has the published exploit signature enabled.",
    "Host firewall denies the vulnerable port from user networks. EDR alerts on the known payload.",
    "The asset is monitored by the lab EDR policy, and the owner reviews the exception before it expires.",
)


@dataclass(frozen=True)
class RiskException:
    exception_id: str
    host_name: str
    cve: str
    owner: str
    justification: str
    compensating_controls: str
    expiry: date
    approver: str

    def __post_init__(self) -> None:
        required = {
            "exception_id": self.exception_id,
            "host_name": self.host_name,
            "cve": self.cve,
            "owner": self.owner,
            "justification": self.justification,
            "compensating_controls": self.compensating_controls,
            "approver": self.approver,
        }
        missing = [name for name, value in required.items() if not str(value).strip()]
        if missing:
            raise ValueError(f"Exception is missing {', '.join(missing)}")
        if not isinstance(self.expiry, date):
            raise ValueError("expiry is required")

    def status(self, as_of: date) -> str:
        return "Active" if self.expiry >= as_of else "Expired"

    def pauses(self, as_of: date) -> bool:
        return self.expiry >= as_of

    def to_dict(self) -> dict:
        return {
            "exception_id": self.exception_id,
            "host_name": self.host_name,
            "cve": self.cve,
            "owner": self.owner,
            "justification": self.justification,
            "compensating_controls": self.compensating_controls,
            "expiry": self.expiry.isoformat(),
            "approver": self.approver,
        }


def finding_key(host_name: object, cve: object) -> str:
    return f"{str(host_name).strip().lower()}|{str(cve).strip().upper()}"


def record_from_dict(payload: dict) -> RiskException:
    expiry = payload.get("expiry")
    if isinstance(expiry, date):
        parsed = expiry
    else:
        year, month, day = (int(part) for part in str(expiry)[:10].split("-"))
        parsed = date(year, month, day)
    return RiskException(
        exception_id=str(payload.get("exception_id") or ""),
        host_name=str(payload.get("host_name") or ""),
        cve=str(payload.get("cve") or "").upper(),
        owner=str(payload.get("owner") or ""),
        justification=str(payload.get("justification") or ""),
        compensating_controls=str(payload.get("compensating_controls") or ""),
        expiry=parsed,
        approver=str(payload.get("approver") or ""),
    )


def index_exceptions(records: list[RiskException], as_of: date) -> dict[str, RiskException]:
    """One record per host and CVE. An active exception wins over an expired one.

    Two active exceptions keep the later expiry.
    """
    chosen: dict[str, RiskException] = {}
    for record in records:
        key = finding_key(record.host_name, record.cve)
        current = chosen.get(key)
        if current is None:
            chosen[key] = record
            continue
        current_active = current.pauses(as_of)
        record_active = record.pauses(as_of)
        if record_active and not current_active:
            chosen[key] = record
        elif record_active and current_active and record.expiry > current.expiry:
            chosen[key] = record
        elif not current_active and not record_active and record.expiry > current.expiry:
            chosen[key] = record
    return chosen


def seed_exceptions(findings: pd.DataFrame, as_of: date, *, limit: int = 8) -> list[RiskException]:
    """Build a stable demo register from the highest-scoring overdue findings."""
    if findings.empty or "sla_status" not in findings.columns:
        return []
    overdue = findings[findings["state"].map(is_open) & (findings["sla_status"] == "Overdue")].copy()
    if overdue.empty:
        return []
    overdue = overdue.sort_values(
        ["score", "cve", "host_name"],
        ascending=[False, True, True],
    )
    picked = overdue.head(limit)
    if len(picked) <= 1:
        active_count = len(picked)
    else:
        active_count = min(5, len(picked) - 1)
    active_offsets = (30, 45, 60, 21, 14)
    expired_offsets = (10, 3, 40)
    records: list[RiskException] = []
    expired_seen = 0
    for index, row in enumerate(picked.itertuples(index=False)):
        active = index < active_count
        if active:
            expiry = as_of + timedelta(days=active_offsets[index % len(active_offsets)])
        else:
            expiry = as_of - timedelta(days=expired_offsets[expired_seen % len(expired_offsets)])
            expired_seen += 1
        host = str(row.host_name)
        cve = str(row.cve).upper()
        owner = str(row.owner or "Unassigned").strip() or "Unassigned"
        records.append(
            RiskException(
                exception_id=f"EX-2604-{index + 1:02d}",
                host_name=host,
                cve=cve,
                owner=owner,
                justification=f"Risk acceptance for {cve} on {host}. {_JUSTIFICATIONS[index % len(_JUSTIFICATIONS)]}",
                compensating_controls=_CONTROLS[index % len(_CONTROLS)],
                expiry=expiry,
                approver=APPROVERS[index % len(APPROVERS)],
            )
        )
    return records


def apply_exceptions(
    findings: pd.DataFrame,
    records: list[RiskException],
    as_of: date,
) -> pd.DataFrame:
    """Mark paused findings and replace their SLA label with Exception.

    The original label is kept on ``sla_status_raw`` so the row can still
    explain the underlying deadline.
    """
    if findings.empty:
        frame = findings.copy()
        for column, value in (
            ("sla_status_raw", ""),
            ("exception_status", ""),
            ("exception_id", ""),
            ("exception_expiry", ""),
            ("exception_approver", ""),
            ("exception_justification", ""),
            ("exception_controls", ""),
            ("sla_paused", False),
        ):
            frame[column] = value
        return frame

    chosen = index_exceptions(records, as_of)
    raw: list[str] = []
    statuses: list[str] = []
    paused: list[bool] = []
    ids: list[str] = []
    expiries: list[str] = []
    approvers: list[str] = []
    justifications: list[str] = []
    controls: list[str] = []
    for row in findings.itertuples(index=False):
        original = str(getattr(row, "sla_status", "") or "")
        raw.append(original)
        record = None
        if is_open(getattr(row, "state", "")):
            record = chosen.get(finding_key(getattr(row, "host_name", ""), getattr(row, "cve", "")))
        if record is None:
            statuses.append("")
            paused.append(False)
            ids.append("")
            expiries.append("")
            approvers.append("")
            justifications.append("")
            controls.append("")
            continue
        statuses.append(record.status(as_of))
        paused.append(record.pauses(as_of))
        ids.append(record.exception_id)
        expiries.append(record.expiry.isoformat())
        approvers.append(record.approver)
        justifications.append(record.justification)
        controls.append(record.compensating_controls)
    frame = findings.copy()
    frame["sla_status_raw"] = raw
    frame["exception_status"] = statuses
    frame["exception_id"] = ids
    frame["exception_expiry"] = expiries
    frame["exception_approver"] = approvers
    frame["exception_justification"] = justifications
    frame["exception_controls"] = controls
    frame["sla_paused"] = paused
    frame.loc[frame["sla_paused"].map(bool), "sla_status"] = "Exception"
    return frame


def exceptions_table(records: list[RiskException], as_of: date) -> pd.DataFrame:
    rows = []
    for record in records:
        rows.append(
            {
                "ID": record.exception_id,
                "Status": record.status(as_of),
                "Expired": "Yes" if record.status(as_of) == "Expired" else "No",
                "Host": record.host_name,
                "CVE": record.cve,
                "Owner": record.owner,
                "Approver": record.approver,
                "Expiry": record.expiry.isoformat(),
                "Justification": record.justification,
                "Compensating controls": record.compensating_controls,
            }
        )
    frame = pd.DataFrame(rows)
    if frame.empty:
        return pd.DataFrame(
            columns=[
                "ID",
                "Status",
                "Expired",
                "Host",
                "CVE",
                "Owner",
                "Approver",
                "Expiry",
                "Justification",
                "Compensating controls",
            ]
        )
    order = {"Expired": 0, "Active": 1}
    frame["_order"] = frame["Status"].map(lambda value: order.get(value, 2))
    return frame.sort_values(["_order", "Expiry", "ID"]).drop(columns=["_order"]).reset_index(drop=True)


def exceptions_to_json(records: list[RiskException]) -> str:
    """Canonical JSON register. This is the file an operator re-imports."""
    return json.dumps([record.to_dict() for record in records], indent=2)


def exceptions_to_csv(records: list[RiskException]) -> str:
    """Canonical CSV register, one exception per row."""
    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(_EXPORT_FIELDS))
    writer.writeheader()
    for record in records:
        writer.writerow({key: spreadsheet_cell(value) for key, value in record.to_dict().items()})
    return buffer.getvalue()


def _normalize_payload(raw: dict) -> dict:
    payload: dict[str, str] = {}
    for key, value in raw.items():
        canonical = _HEADER_ALIASES.get(str(key).strip().lower())
        if canonical is None or canonical == "_ignore":
            continue
        payload[canonical] = "" if value is None else str(from_spreadsheet_cell(str(value).strip()))
    return payload


def records_from_payloads(payloads: list[dict]) -> tuple[list[RiskException], list[str]]:
    """Parse exception dicts. Invalid rows are returned as error strings."""
    records: list[RiskException] = []
    errors: list[str] = []
    for index, raw in enumerate(payloads, start=1):
        if not isinstance(raw, dict):
            errors.append(f"Row {index} is not an object.")
            continue
        payload = _normalize_payload(raw)
        if not any(payload.values()):
            continue
        try:
            records.append(record_from_dict(payload))
        except (ValueError, TypeError) as exc:
            errors.append(f"Row {index}: {exc}")
    return records, errors


def exceptions_from_json(text: str) -> tuple[list[RiskException], list[str]]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        return [], [f"JSON could not be read: {exc.msg}"]
    if isinstance(payload, dict) and "exceptions" in payload:
        payload = payload["exceptions"]
    if isinstance(payload, dict) and "extra" in payload:
        payload = payload["extra"]
    if not isinstance(payload, list):
        return [], ["JSON must be a list of exceptions."]
    return records_from_payloads(payload)


def exceptions_from_csv(text: str) -> tuple[list[RiskException], list[str]]:
    if not str(text).strip():
        return [], ["The CSV is empty."]
    try:
        reader = csv.DictReader(StringIO(text))
        rows = list(reader)
    except csv.Error as exc:
        return [], [f"CSV could not be read: {exc}"]
    if reader.fieldnames is None:
        return [], ["The CSV has no header row."]
    return records_from_payloads(rows)


def load_operator_register(path: Path | None = None) -> dict:
    """Read the gitignored operator file. Missing file means an empty register."""
    target = path or OPERATOR_REGISTER
    if not target.exists():
        return {"extra": [], "removed": [], "seq": 0}
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"extra": [], "removed": [], "seq": 0}
    if not isinstance(payload, dict):
        return {"extra": [], "removed": [], "seq": 0}
    extra = payload.get("extra") if isinstance(payload.get("extra"), list) else []
    removed = payload.get("removed") if isinstance(payload.get("removed"), list) else []
    try:
        seq = int(payload.get("seq") or 0)
    except (TypeError, ValueError):
        seq = 0
    return {"extra": extra, "removed": [str(item) for item in removed], "seq": seq}


def save_operator_register(state: dict, path: Path | None = None) -> None:
    """Write operator-added exceptions. The demo seed is not stored here."""
    target = path or OPERATOR_REGISTER
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "extra": list(state.get("extra") or []),
        "removed": list(state.get("removed") or []),
        "seq": int(state.get("seq") or 0),
    }
    target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
