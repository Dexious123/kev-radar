"""Behaviour that matters once the app is public: shared state, uploads, and parsing edge cases."""

from datetime import date
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pandas as pd
import pytest

from kev_radar.bod import OUTCOME_14
from kev_radar.enrich import supplement_ssvc
from kev_radar.exceptions import MAX_IMPORT_ROWS, enforce_import_limit, operator_file_enabled
from kev_radar.metrics import slo_compliance
from kev_radar.msrc import _executable_text, remediation_violations, render_audit_script
from kev_radar.overview import fix_reason
from kev_radar.parse import ParseError, _parse_float, parse_findings

ROOT = Path(__file__).resolve().parents[1]
AS_OF = date(2026, 10, 16)


# --- Exceptions register: one visitor must not change what another sees ---


def test_operator_file_is_off_unless_explicitly_enabled():
    assert operator_file_enabled({}) is False
    assert operator_file_enabled({"KEV_RADAR_OPERATOR_FILE": ""}) is False
    assert operator_file_enabled({"KEV_RADAR_OPERATOR_FILE": "0"}) is False
    for value in ("1", "true", "YES"):
        assert operator_file_enabled({"KEV_RADAR_OPERATOR_FILE": value}) is True


def test_an_oversized_import_is_refused_whole():
    records, errors = enforce_import_limit(list(range(MAX_IMPORT_ROWS)))
    assert len(records) == MAX_IMPORT_ROWS and errors == []
    records, errors = enforce_import_limit(list(range(MAX_IMPORT_ROWS + 1)))
    assert records == []
    assert "nothing was imported" in errors[0]


def test_the_app_shares_no_register_file_by_default_and_renders_free_text_plainly():
    source = (ROOT / "streamlit_app.py").read_text(encoding="utf-8")
    persist = source[source.index("def _persist_exceptions"):source.index("def _estate_exceptions")]
    assert "if not operator_file_enabled():" in persist
    assert "load_operator_register() if operator_file_enabled() else" in source
    assert 'st.text(str(row.get("exception_justification")' in source
    assert 'st.markdown(str(row.get("exception_justification")' not in source
    assert "enforce_import_limit(loaded)" in source


def test_uploads_are_size_limited():
    config = (ROOT / ".streamlit" / "config.toml").read_text(encoding="utf-8")
    assert "maxUploadSize = 10" in config


# --- Vulnrichment lookups resume with the next batch ---


def test_ssvc_lookups_move_through_a_long_upload_batch_by_batch():
    cves = [f"CVE-2026-{n:05d}" for n in range(60)]
    calls: list[str] = []

    def fetch(cve: str) -> dict:
        calls.append(cve)
        return {"found": True, "automatable": "no", "technical_impact": "partial"}

    resolved: dict = {}
    for expected_skipped in (40, 20, 0):
        merged, report = supplement_ssvc({}, cves, fetch=fetch, limit=20, resolved=resolved)
        assert len(report["skipped"]) == expected_skipped
    assert len(calls) == 60
    assert len(set(calls)) == 60, "no CVE is looked up twice"
    assert all(cve in merged for cve in cves)
    assert len(report["fetched"]) == 60


def test_a_404_is_remembered_and_a_failure_is_retried():
    attempts: dict[str, int] = {}

    def fetch(cve: str) -> dict:
        attempts[cve] = attempts.get(cve, 0) + 1
        if cve.endswith("1"):
            return {"found": False}
        raise RuntimeError("network")

    resolved: dict = {}
    for _ in range(2):
        _, report = supplement_ssvc({}, ["CVE-2026-00001", "CVE-2026-00002"], fetch=fetch, resolved=resolved)
    assert attempts == {"CVE-2026-00001": 1, "CVE-2026-00002": 2}
    assert report["not_published"] == ["CVE-2026-00001"]
    assert report["failed"] == ["CVE-2026-00002"]


# --- Parsing ---


def test_scientific_notation_is_read_as_a_number_not_its_mantissa():
    assert _parse_float("9.7e-05") == pytest.approx(9.7e-05)
    assert _parse_float("1E-3") == pytest.approx(0.001)
    assert _parse_float("7.5 / 9.8") == 7.5
    assert _parse_float("NaN") is None
    assert _parse_float("inf") is None


def test_a_malformed_csv_is_a_parse_error_not_a_traceback():
    with pytest.raises(ParseError, match="could not be read"):
        parse_findings(StringIO('CVE,Host\n"CVE-2024-1,h'))


# --- PowerShell audit ---


def test_a_host_named_like_a_blocked_cmdlet_does_not_block_the_audit():
    script = render_audit_script(
        [{"cve": "CVE-2021-34527", "kb": "KB5004947", "products": ["Windows Server 2019"]}],
        hosts=["wusa.corp.example", "dism"],
    )
    assert "# - wusa.corp.example" in script
    assert "Get-HotFix" in script


def test_the_guard_still_sees_a_cmdlet_in_executable_lines():
    text = _executable_text("# wusa is just a host name\nwusa.exe /uninstall\n$x = @'\nwusa,data\n'@ | ConvertFrom-Csv")
    assert "# wusa" not in text
    assert "wusa,data" not in text
    assert "wusa.exe /uninstall" in text
    assert "'@ | ConvertFrom-Csv" in text
    assert remediation_violations(text)


# --- Metrics and wording ---


def test_a_closed_row_without_a_fix_date_is_not_an_slo_miss():
    frame = pd.DataFrame(
        [
            {"state": "fixed", "outcome": OUTCOME_14, "deadline": date(2026, 10, 1), "last_fixed": None, "sla_paused": False},
            {"state": "open", "outcome": OUTCOME_14, "deadline": date(2026, 11, 1), "last_fixed": None, "sla_paused": False},
        ]
    )
    result = slo_compliance(frame, AS_OF)
    assert result == {"eligible": 1, "compliant": 1, "percent": 100.0}


def test_one_day_is_singular():
    overdue = SimpleNamespace(sla_status="Overdue", days_left=-1)
    due = SimpleNamespace(sla_status="Due soon", days_left=1)
    assert fix_reason(overdue, AS_OF).startswith("1 day overdue")
    assert fix_reason(due, AS_OF).startswith("due in 1 day")
    assert "days" not in fix_reason(overdue, AS_OF).split("·")[0]
