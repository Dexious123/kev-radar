"""Executive briefings and ticket drafts, checked against the queue.

Offline template mode is the default and needs no key. A live model is called
only when the caller passes an API key at runtime. The key is an Authorization
header, never part of the prompt and never written by this module.

The checker rejects any CVE ID, hostname, IPv4 address, or number in the
output that is not present in the facts payload. Presence is the test the
portfolio spec asks for: a number copied from a different field still passes.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation

import pandas as pd
import requests

from kev_radar.metrics import is_open

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
HOST_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:[A-Za-z]{2,})\b"
)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
NUMBER_RE = re.compile(r"\d+(?:\.\d+)?")

DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"
ESTATE_NAME = "Harborline Mutual lab"

_SYSTEM = (
    "Write a short executive briefing and one remediation ticket per owner. "
    "Use only values that appear in the user JSON. "
    "Do not invent a CVE identifier, a hostname, an IP address, or a number. "
    "If a figure is not in the JSON, leave it out."
)


@dataclass(frozen=True)
class FactCheck:
    passed: bool
    violations: tuple[str, ...]


def display_number(value: object) -> str:
    """Canonical number text shared by the template and the checker."""
    try:
        number = Decimal(str(value))
    except (InvalidOperation, ValueError):
        return str(value)
    if number == number.to_integral():
        return str(number.to_integral())
    return format(number.normalize(), "f")


def _collect_numbers(value: object, into: set[str]) -> None:
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, (int, float, Decimal)):
        into.add(display_number(value))
        return
    if isinstance(value, str):
        for match in NUMBER_RE.findall(value):
            into.add(display_number(match))
        return
    if isinstance(value, dict):
        for item in value.values():
            _collect_numbers(item, into)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _collect_numbers(item, into)


def _ipv4_ok(text: str) -> bool:
    parts = text.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def build_facts(
    frame: pd.DataFrame,
    stats: dict,
    records: list,
    as_of: str,
    *,
    estate: str = ESTATE_NAME,
) -> dict:
    """Structured input for both the template and a live model."""
    forecast = stats["forecast"]
    slo = stats["slo"]
    average = stats.get("mttr")
    findings: list[dict] = []
    if not frame.empty:
        open_rows = frame[frame["state"].map(is_open)].head(8)
        for row in open_rows.itertuples(index=False):
            deadline = getattr(row, "deadline", None)
            deadline_text = "" if deadline is None or pd.isna(deadline) else str(deadline)[:10]
            findings.append(
                {
                    "cve": str(row.cve).upper(),
                    "host_name": str(row.host_name),
                    "owner": str(row.owner or "Unassigned"),
                    "business_unit": str(row.business_unit or "Unassigned"),
                    "deadline": deadline_text,
                    "score": display_number(round(float(row.score), 1)),
                    "sla_status": str(row.sla_status),
                }
            )
    as_of_date = date.fromisoformat(as_of)
    exceptions: list[dict] = []
    for record in records:
        exceptions.append(
            {
                "exception_id": record.exception_id,
                "cve": record.cve.upper(),
                "host_name": record.host_name,
                "owner": record.owner,
                "approver": record.approver,
                "expiry": record.expiry.isoformat(),
                "status": record.status(as_of_date),
            }
        )
    exceptions = exceptions[:5]
    payload = {
        "estate": estate,
        "as_of": as_of,
        "directive": "BOD 26-04",
        "window_days": int(forecast.window_days),
        "history_weeks": int(forecast.history_days // 7),
        "open_findings": int(stats["open"]),
        "overdue": int(stats["overdue"]),
        "due_in_window": int(stats["due_soon"]),
        "projected_misses": int(forecast.projected_misses),
        "weekly_close_rate": display_number(forecast.weekly_close_rate),
        "slo_percent": display_number(slo["percent"]),
        "average_days_to_fix": None if average is None else display_number(round(float(average), 1)),
        "active_exceptions": int(stats.get("active_exceptions", 0)),
        "expired_exceptions": int(stats.get("expired_exceptions", 0)),
        "findings": findings,
        "exceptions": exceptions,
    }
    return payload


def render_offline(facts: dict) -> dict[str, str]:
    """Template briefing. Every figure is copied from ``facts``."""
    estate = facts["estate"]
    as_of = facts["as_of"]
    summary = [
        f"{estate}, as of {as_of}.",
        "",
        (
            f"{facts['open_findings']} findings are still open. "
            f"{facts['overdue']} are past the {facts['directive']} deadline. "
            f"{facts['due_in_window']} are due within {facts['window_days']} days. "
            f"At {facts['weekly_close_rate']} closes a week over the last {facts['history_weeks']} weeks, "
            f"about {facts['projected_misses']} of those {facts['due_in_window']} are projected to miss."
        ),
        (
            f"SLO compliance is {facts['slo_percent']} percent."
        ),
    ]
    if facts.get("average_days_to_fix") is None:
        summary.append("Average time to fix is unavailable because nothing in this filter is closed.")
    else:
        summary.append(
            f"Average time to fix on closed findings is {facts['average_days_to_fix']} days."
        )
    summary.append(
        f"{facts['active_exceptions']} active exceptions pause SLA breach counting. "
        f"{facts['expired_exceptions']} exceptions have expired, so those findings are counted again."
    )
    findings = facts.get("findings") or []
    if findings:
        top = findings[0]
        when = top["deadline"] or "no day-count deadline"
        summary.append(
            f"Highest open score: {top['cve']} on {top['host_name']}, "
            f"owner {top['owner']}, business unit {top['business_unit']}, "
            f"deadline {when}, score {top['score']}, status {top['sla_status']}."
        )
    else:
        summary.append("No open findings are in this filter.")
    for item in facts.get("exceptions") or []:
        if item.get("status") != "Active":
            continue
        summary.append(
            f"Active exception {item['exception_id']} covers {item['cve']} on {item['host_name']} "
            f"until {item['expiry']}, approved by {item['approver']}."
        )
        break

    tickets: list[str] = []
    by_owner: dict[str, list[dict]] = {}
    for item in findings:
        by_owner.setdefault(item["owner"], []).append(item)
    for owner, rows in by_owner.items():
        lines = [
            f"Owner: {owner}",
            f"Business unit: {rows[0]['business_unit']}",
            "Findings in this draft:",
        ]
        for item in rows:
            when = item["deadline"] or "no day-count deadline"
            lines.append(
                f"- {item['cve']} on {item['host_name']}, deadline {when}, "
                f"score {item['score']}, status {item['sla_status']}."
            )
        tickets.append("\n".join(lines))

    parts = ["\n".join(summary), "", "## Tickets", ""]
    if tickets:
        parts.append("\n\n".join(tickets))
    else:
        parts.append("No ticket drafts. The filter has no open findings.")
    markdown = "\n".join(parts).strip() + "\n"
    return {"summary": "\n".join(summary).strip() + "\n", "tickets": "\n\n".join(tickets), "markdown": markdown}


def check_text(text: str, facts: dict) -> FactCheck:
    """Reject CVE IDs, hostnames, IPv4 addresses, and numbers that are not in ``facts``."""
    allowed_cves = {match.group(0).upper() for match in CVE_RE.finditer(json.dumps(facts))}
    allowed_hosts = {match.group(0).lower() for match in HOST_RE.finditer(json.dumps(facts))}
    allowed_ips = {match.group(0) for match in IPV4_RE.finditer(json.dumps(facts)) if _ipv4_ok(match.group(0))}
    allowed_numbers: set[str] = set()
    _collect_numbers(facts, allowed_numbers)

    violations: list[str] = []
    for match in CVE_RE.finditer(text):
        cve = match.group(0).upper()
        if cve not in allowed_cves:
            violations.append(f"CVE {cve} is not in the input")
    for match in HOST_RE.finditer(text):
        host = match.group(0).lower()
        if host not in allowed_hosts:
            violations.append(f"Hostname {match.group(0)} is not in the input")
    for match in IPV4_RE.finditer(text):
        ip = match.group(0)
        if _ipv4_ok(ip) and ip not in allowed_ips:
            violations.append(f"IP address {ip} is not in the input")
    for match in NUMBER_RE.finditer(text):
        token = display_number(match.group(0))
        if token not in allowed_numbers:
            violations.append(f"Number {match.group(0)} is not in the input")
    # Preserve order while dropping repeats.
    unique = tuple(dict.fromkeys(violations))
    return FactCheck(passed=not unique, violations=unique)


def chat_body(facts: dict, model: str) -> dict:
    return {
        "model": model,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": _SYSTEM},
            {"role": "user", "content": json.dumps(facts, sort_keys=True)},
        ],
    }


def resolve_llm_settings(*, api_key: str | None = None, model: str | None = None) -> dict[str, str]:
    """Settings for one live briefing call.

    The key is only ever the one passed in, which is the key the visitor typed.
    There is deliberately no fallback to an environment variable or a Streamlit
    secret: on a public deployment any anonymous visitor could spend it.

    The endpoint comes from configuration only (environment, then a Streamlit
    secret, then the default) and is never taken from the page, so a visitor
    cannot point the request, or its Authorization header, at another server.
    Nothing is written to disk. A missing secrets file is ignored.
    """
    key = (api_key or "").strip()
    url = (os.environ.get("KEV_RADAR_LLM_BASE_URL") or _streamlit_secret("KEV_RADAR_LLM_BASE_URL") or DEFAULT_BASE_URL).strip()
    chosen = (
        (model or "").strip()
        or os.environ.get("KEV_RADAR_LLM_MODEL")
        or _streamlit_secret("KEV_RADAR_LLM_MODEL")
        or DEFAULT_MODEL
    ).strip()
    return {"api_key": key, "base_url": url.rstrip("/"), "model": chosen}


def _streamlit_secret(name: str) -> str:
    try:
        import streamlit as st

        secrets = st.secrets
        if name in secrets and secrets[name]:
            return str(secrets[name]).strip()
    except Exception:
        return ""
    return ""


def complete_live(facts: dict, *, api_key: str, base_url: str, model: str, timeout: float = 40) -> str:
    """Call an OpenAI-compatible chat endpoint. The key stays in the header."""
    if not api_key.strip():
        raise RuntimeError("No API key. Offline template mode is the default.")
    if not base_url.strip().lower().startswith("https://"):
        raise RuntimeError("The live endpoint must use https. No request was sent.")
    response = requests.post(
        f"{base_url.rstrip('/')}/chat/completions",
        json=chat_body(facts, model),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "kev-radar-portfolio/1.0 (public-data demo)",
        },
        timeout=timeout,
    )
    response.raise_for_status()
    payload = response.json()
    try:
        return str(payload["choices"][0]["message"]["content"])
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError("The model response did not include a message.") from exc
