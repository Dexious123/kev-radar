"""Fact check for executive briefings and ticket drafts."""

from datetime import date

import pandas as pd

from kev_radar.briefing import (
    build_facts,
    chat_body,
    check_text,
    render_offline,
    resolve_llm_settings,
)
from kev_radar.exceptions import RiskException
from kev_radar.metrics import BreachForecast

AS_OF = date(2026, 10, 16)


def _facts() -> dict:
    frame = pd.DataFrame(
        [
            {
                "state": "open",
                "cve": "CVE-2024-21351",
                "host_name": "hl-pay-srv-001.lab.invalid",
                "owner": "Priya Shah",
                "business_unit": "Payments",
                "deadline": date(2026, 10, 20),
                "score": 88.4,
                "sla_status": "Due soon",
            }
        ]
    )
    forecast = BreachForecast(
        history_days=28,
        window_days=7,
        closed_in_history=4,
        weekly_close_rate=1.0,
        due_in_window=1,
        projected_misses=0,
        already_overdue=0,
        paused=1,
        statement="Projection",
    )
    stats = {
        "open": 1,
        "overdue": 0,
        "due_soon": 1,
        "forecast": forecast,
        "slo": {"percent": 50.0, "eligible": 2, "compliant": 1},
        "mttr": 12.0,
        "active_exceptions": 1,
        "expired_exceptions": 0,
    }
    record = RiskException(
        exception_id="EX-2604-01",
        host_name="hl-pay-srv-001.lab.invalid",
        cve="CVE-2024-21351",
        owner="Priya Shah",
        justification="Queued for the next change window.",
        compensating_controls="Management VLAN only.",
        expiry=date(2026, 11, 15),
        approver="Morgan Ellis",
    )
    return build_facts(frame, stats, [record], AS_OF.isoformat())


def test_offline_briefing_and_tickets_pass_the_checker():
    facts = _facts()
    rendered = render_offline(facts)
    assert "Priya Shah" in rendered["tickets"]
    assert "CVE-2024-21351" in rendered["markdown"]
    result = check_text(rendered["markdown"], facts)
    assert result.passed, result.violations


def test_checker_rejects_unknown_cve_host_and_number():
    facts = _facts()
    text = render_offline(facts)["markdown"]
    cve = check_text(text + "\nAlso fix CVE-2099-9999.\n", facts)
    assert any("CVE-2099-9999" in item for item in cve.violations)
    host = check_text(text + "\nHost ghost.example.com is affected.\n", facts)
    assert any("ghost.example.com" in item for item in host.violations)
    number = check_text(text + "\n999991 hosts remain.\n", facts)
    assert any("999991" in item for item in number.violations)
    invented_ip = check_text(text + "\nScan 203.0.113.50 next.\n", facts)
    assert any("203.0.113.50" in item for item in invented_ip.violations)


def test_checker_allows_values_that_are_in_the_facts():
    facts = _facts()
    assert check_text("CVE-2024-21351 on hl-pay-srv-001.lab.invalid scored 88.4", facts).passed


def test_live_request_does_not_carry_the_api_key():
    facts = _facts()
    secret = "sk-test-not-a-real-key"
    body = chat_body(facts, "gpt-4o-mini")
    assert secret not in str(body)
    settings = resolve_llm_settings(api_key=secret, model="gpt-4o-mini")
    assert settings["api_key"] == secret
    assert settings["api_key"] not in str(chat_body(facts, settings["model"]))
