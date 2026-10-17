"""KEV Radar — BOD 26-04 remediation console for a synthetic estate.

Run locally:

    streamlit run streamlit_app.py --server.port 8741
"""

from __future__ import annotations

import html
from datetime import date, timedelta

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from kev_radar.bod import (
    CERT_TABLE_URL,
    DIRECTIVE_URL,
    FORENSIC_TRIAGE_NOTE,
    FORENSIC_TRIAGE_STEPS,
    GUIDANCE_URL,
    VULNRICHMENT_REPO,
)
from kev_radar.briefing import (
    build_facts,
    check_text,
    complete_live,
    render_offline,
    resolve_llm_settings,
)
from kev_radar.enrich import fetch_enrichment, ssvc_from_enrichment, supplement_ssvc
from kev_radar.exceptions import (
    RiskException,
    apply_exceptions,
    enforce_import_limit,
    exceptions_from_csv,
    exceptions_from_json,
    exceptions_table,
    exceptions_to_csv,
    exceptions_to_json,
    finding_key,
    load_operator_register,
    operator_file_enabled,
    record_from_dict,
    save_operator_register,
    seed_exceptions,
)
from kev_radar.feeds import (
    DEMO_CSV,
    fetch_epss,
    fetch_kev,
    load_bundle,
    snapshot_age_hours,
)
from kev_radar.generate import DEMO_SEED, generate_csv
from kev_radar.kevdiff import (
    EstateHit,
    kev_this_week,
    render_monday_report,
    triage_label,
)
from kev_radar.metrics import (
    aging_buckets,
    breach_forecast,
    burndown,
    is_open,
    mean_time_to_fix,
    outcome_mix,
    slo_compliance,
)
from kev_radar.msrc import is_windows_text, lookup_cve_live, patches_for, render_audit_script
from kev_radar.overview import headline, projected_burndown, risk_trend, top_to_fix
from kev_radar.parse import ParseError, ParseResult, parse_findings
from kev_radar.present import (
    csv_download,
    kev_additions_by_month,
    queue_frame,
    scatter_frame,
    vendor_frame,
)
from kev_radar.prioritize import prioritize
from kev_radar.report import render_html_report, render_tickets
from kev_radar.simulate import cves_addressed_by_kb, select_open_keys, simulate
from kev_radar.surface import exposure_heatmap, heatmap_matrix, host_findings, host_index

AS_OF = date.today()
OPEN = {"open", "reopened"}

st.set_page_config(
    page_title="KEV Radar",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Source+Sans+3:wght@400;600;700&display=swap');
    html, body, [class*="css"] {font-family: "Source Sans 3", "Segoe UI", sans-serif;}
    .block-container {padding-top: 1.05rem; padding-bottom: 2.4rem; max-width: 1180px;}
    div[data-testid="stMetric"] {
        background: linear-gradient(180deg, #182230 0%, #141c27 100%);
        border: 1px solid #2c3d52;
        border-top: 2px solid #e0a33a;
        border-radius: 12px;
        padding: 0.55rem 0.8rem 0.4rem 0.8rem;
    }
    div[data-testid="stMetricLabel"] {font-size: 0.86rem;}
    .banner {
        background: linear-gradient(135deg, #16202c 0%, #101820 70%);
        border: 1px solid #2c4156;
        border-radius: 14px;
        padding: 0.95rem 1.1rem 0.8rem 1.1rem;
        margin-bottom: 0.85rem;
    }
    .kicker {
        letter-spacing: 0.16em;
        text-transform: uppercase;
        color: #e0a33a;
        font-size: 0.72rem;
        font-weight: 700;
        margin: 0 0 0.25rem 0;
    }
    .banner h1 {font-size: 1.85rem; margin: 0 0 0.25rem 0; letter-spacing: -0.03em; font-weight: 700;}
    .banner p {margin: 0.18rem 0; color: #c5d2e0;}
    .path {
        font-family: "IBM Plex Mono", ui-monospace, Menlo, Consolas, monospace;
        font-size: 0.92rem;
        line-height: 1.5;
        background: #101820;
        border-left: 3px solid #e0a33a;
        padding: 0.75rem 0.9rem;
        border-radius: 8px;
        margin: 0.2rem 0 0.6rem 0;
    }
    .note {color: #9fb0c2; font-size: 0.92rem;}
    section[data-testid="stSidebar"] {border-right: 1px solid #243140;}
    </style>
    """,
    unsafe_allow_html=True,
)

PAGES = (
    "Overview",
    "Fix queue",
    "Attack surface",
    "What-if",
    "Remediation",
    "KEV this week",
    "Windows patches",
    "Briefing",
    "Signals",
    "About",
)


@st.cache_data(ttl=86400, show_spinner=False)
def cached_bundle() -> dict:
    return load_bundle()


@st.cache_data(ttl=86400, show_spinner=False)
def cached_live_kev() -> dict:
    """Daily live pull of the CISA KEV catalog. Failures are not cached."""
    return fetch_kev()


@st.cache_data(ttl=86400, show_spinner=False)
def cached_epss(cves: tuple[str, ...]) -> dict[str, dict]:
    rows = fetch_epss(list(cves))
    scores = {}
    for row in rows:
        cve = str(row.get("cve") or "").upper()
        if cve and row.get("epss") is not None:
            scores[cve] = {"epss": float(row["epss"]), "percentile": row.get("percentile")}
    return scores


@st.cache_data(ttl=86400, show_spinner=False)
def cached_msrc_cve(cve: str) -> dict:
    """Live MSRC lookup for one CVE missing from the snapshot. Failures are not cached."""
    return lookup_cve_live(cve)


@st.cache_data(ttl=86400, show_spinner=False)
def cached_enrichment(cve: str) -> dict:
    """One Vulnrichment record. A network error is not cached; a 404 is."""
    return fetch_enrichment(cve)


@st.cache_data(ttl=86400, show_spinner=False, max_entries=8)
def cached_parse(csv_text: str) -> dict:
    """Parse a findings CSV once. Scoring still runs, and it is much smaller."""
    from io import StringIO

    parsed = parse_findings(StringIO(csv_text))
    return {
        "findings": parsed.findings,
        "raw_rows": parsed.raw_rows,
        "collapsed_findings": parsed.collapsed_findings,
        "warnings": tuple(parsed.warnings),
    }


@st.cache_data(ttl=86400, show_spinner=False)
def cached_estate(seed: int, as_of_iso: str, catalog_version: str) -> str:
    bundle = load_bundle()
    return generate_csv(bundle["pool"], as_of=date.fromisoformat(as_of_iso), seed=int(seed))


def _style(fig):
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#e7eef6",
        margin=dict(l=8, r=8, t=36, b=8),
        legend=dict(bgcolor="rgba(0,0,0,0)"),
    )
    fig.update_xaxes(gridcolor="#243140", zerolinecolor="#243140")
    fig.update_yaxes(gridcolor="#243140", zerolinecolor="#243140")
    return fig


def _catalog_from(bundle: dict) -> tuple[dict, str]:
    age = snapshot_age_hours(bundle.get("metadata") or {})
    if age is not None and age <= 20:
        version = (bundle.get("metadata") or {}).get("kev_catalog_version", "snapshot")
        return bundle["catalog"], f"bundled snapshot {version}"
    try:
        live = cached_live_kev()
    except Exception:
        version = (bundle.get("metadata") or {}).get("kev_catalog_version", "snapshot")
        return bundle["catalog"], f"bundled snapshot {version} (live feed unavailable)"
    if live.get("vulnerabilities"):
        return live, f"live CISA feed {live.get('catalogVersion', '')}".strip()
    version = (bundle.get("metadata") or {}).get("kev_catalog_version", "snapshot")
    return bundle["catalog"], f"bundled snapshot {version}"


def _merge_epss(base: dict, cves: list[str]) -> dict:
    missing = tuple(sorted({cve for cve in cves if cve and cve not in base}))
    if not missing:
        return base
    # One FIRST call covers at most 100 CVEs. Enough for a demo upload.
    try:
        extra = cached_epss(missing[:100])
    except Exception:
        return base
    merged = dict(base)
    merged.update(extra)
    return merged


def _restore_parse(csv_text: str):
    payload = cached_parse(csv_text)
    return ParseResult(
        findings=payload["findings"],
        raw_rows=int(payload["raw_rows"]),
        collapsed_findings=int(payload["collapsed_findings"]),
        skipped_no_cve=0,
        skipped_no_host=0,
        duplicate_rows=0,
        warnings=list(payload["warnings"]),
    )


def _load_estate(mode: str, upload, seed: int, catalog_version: str):
    if mode == "Upload CSV":
        if upload is None:
            return None
        text = upload.getvalue().decode("utf-8", errors="replace")
        return _restore_parse(text)
    if mode == "Regenerate":
        return _restore_parse(cached_estate(seed, AS_OF.isoformat(), catalog_version))
    return _restore_parse(DEMO_CSV.read_text(encoding="utf-8"))


def _live_ssvc(snapshot: dict, cves: list[str]) -> tuple[dict, dict]:
    """Fetch Vulnrichment for CVEs the snapshot does not already contain."""

    def fetch(cve: str) -> dict:
        cleaned = ssvc_from_enrichment(cached_enrichment(cve))
        if cleaned is None:
            return {"found": False}
        cleaned["found"] = True
        return cleaned

    resolved = st.session_state.setdefault("ssvc_resolved", {})
    return supplement_ssvc(snapshot, cves, fetch=fetch, limit=40, resolved=resolved)


def _apply_scope(frame: pd.DataFrame, *, units, owners, exposure, kev_only, ransomware_only, query) -> pd.DataFrame:
    scoped = frame
    if units:
        scoped = scoped[scoped["business_unit"].isin(units)]
    if owners:
        scoped = scoped[scoped["owner"].isin(owners)]
    if exposure == "Publicly exposed":
        scoped = scoped[scoped["exposed"].map(bool)]
    elif exposure == "Internal":
        scoped = scoped[~scoped["exposed"].map(bool)]
    if kev_only:
        scoped = scoped[scoped["in_kev"].map(bool)]
    if ransomware_only:
        scoped = scoped[scoped["ransomware"].map(bool)]
    if query:
        needle = query.strip().lower()
        blob = (
            scoped["cve"].fillna("").str.lower()
            + " "
            + scoped["host_name"].fillna("").str.lower()
            + " "
            + scoped["owner"].fillna("").str.lower()
            + " "
            + scoped["vuln_name"].fillna("").str.lower()
        )
        scoped = scoped[blob.str.contains(needle, regex=False)]
    return scoped


def _estate_hits(frame: pd.DataFrame) -> dict[str, list[EstateHit]]:
    hits: dict[str, list[EstateHit]] = {}
    if frame.empty:
        return hits
    open_rows = frame[frame["state"].map(is_open)]
    for record in open_rows.to_dict(orient="records"):
        hit = EstateHit(
            host_name=str(record.get("host_name") or ""),
            owner=str(record.get("owner") or ""),
            business_unit=str(record.get("business_unit") or ""),
            exposed=bool(record.get("exposed")),
            state=str(record.get("state") or ""),
        )
        hits.setdefault(str(record.get("cve")), []).append(hit)
    return hits


def _metrics(frame: pd.DataFrame) -> dict:
    forecast = breach_forecast(frame, AS_OF)
    if frame.empty:
        return {
            "open": 0,
            "overdue": 0,
            "due_soon": 0,
            "forecast": forecast,
            "slo": {"percent": 0.0, "eligible": 0, "compliant": 0},
            "mttr": None,
            "active_exceptions": 0,
            "expired_exceptions": 0,
        }
    open_rows = frame[frame["state"].map(is_open)]
    active = expired = 0
    if not open_rows.empty and "exception_status" in open_rows.columns:
        active = int((open_rows["exception_status"] == "Active").sum())
        expired = int((open_rows["exception_status"] == "Expired").sum())
    mttr = mean_time_to_fix(frame)
    average = None if mttr.empty else float(mttr.iloc[0]["average_days"])
    return {
        "open": int(len(open_rows)),
        "overdue": int(forecast.already_overdue),
        "due_soon": int(forecast.due_in_window),
        "forecast": forecast,
        "slo": slo_compliance(frame, AS_OF),
        "mttr": average,
        "active_exceptions": active,
        "expired_exceptions": expired,
    }


def _show_metrics(stats: dict) -> None:
    forecast = stats["forecast"]
    top = st.columns(4)
    bottom = st.columns(4)
    top[0].metric(
        "Open findings",
        f"{stats['open']:,}",
        help="Host and CVE pairs still open or reopened in this filter.",
    )
    top[1].metric(
        "Overdue",
        f"{stats['overdue']:,}",
        help="Open findings past the BOD 26-04 deadline. Active exceptions are excluded. The due date itself is still on time.",
    )
    top[2].metric(
        "Due in 7 days",
        f"{stats['due_soon']:,}",
        help="Open findings whose deadline falls in the next 7 days, not counting rows already overdue or paused.",
    )
    top[3].metric(
        "Under exception",
        f"{stats.get('active_exceptions', 0):,}",
        help="Open findings with an active risk acceptance. The SLA clock is paused through the expiry date.",
    )
    bottom[0].metric(
        "Projected SLA misses",
        f"{forecast.projected_misses:,}",
        help="A rate sketch: findings due in 7 days minus the closes expected from the last 4 weeks. Not a prediction.",
    )
    bottom[1].metric(
        "SLO compliance",
        f"{stats['slo']['percent']:.0f}%",
        help="Share of findings that have a day-count deadline and were fixed on time, or are still open and not yet due. Fix-on-upgrade and paused rows are excluded.",
    )
    mttr = "—" if stats["mttr"] is None else f"{stats['mttr']:.0f}d"
    bottom[2].metric(
        "Avg time to fix",
        mttr,
        help="Mean days from first seen to last fixed, on closed findings. This is repair time, not the BOD clock.",
    )
    bottom[3].metric(
        "Expired exceptions",
        f"{stats.get('expired_exceptions', 0):,}",
        help="Open findings whose risk acceptance has lapsed. They count toward breaches again.",
    )


def _detail(row: pd.Series, classic: bool) -> None:
    title = f"{row['cve']} on {row['host_name']}"
    st.subheader(title)
    st.caption(str(row.get("vuln_name") or ""))
    path = row["ssvc_path"] if classic else row["decision_path"]
    st.markdown(f'<div class="path">{html.escape(str(path))}</div>', unsafe_allow_html=True)
    if classic:
        st.markdown(
            '<p class="note">Classic CISA SSVC (Track / Track* / Attend / Act) is a second view. '
            "The remediation deadline below still comes from BOD 26-04. Mission &amp; well-being "
            "is not in the Vulnrichment feed, so the level in the sidebar is your input.</p>",
            unsafe_allow_html=True,
        )
    left, right = st.columns(2)
    with left:
        st.markdown(f"**Asset deadline.** {row['deadline'] or 'No day-count deadline'}")
        st.markdown(f"**SLA.** {row['sla_status']}")
        st.markdown(row["clock_reason"])
        if row.get("kev_due_date") and row.get("deadline") and str(row["kev_due_date"])[:10] != str(row["deadline"])[:10]:
            st.markdown(
                f"CISA's catalog due date is **{str(row['kev_due_date'])[:10]}**. "
                "That date is not asset-specific. This row uses the BOD 26-04 path for this host."
            )
        if row.get("assumption_notes"):
            st.markdown(row["assumption_notes"])
        st.markdown(row.get("exposure_reason") or "")
    with right:
        st.markdown(f"**Priority.** {row['band']} · {row['score']:.1f}")
        st.markdown(row["score_summary"])
        epss = "unavailable" if row["epss"] is None or pd.isna(row["epss"]) else f"{float(row['epss']):.1%}"
        cvss = "unavailable" if row["cvss"] is None or pd.isna(row["cvss"]) else f"{float(row['cvss']):.1f}"
        st.markdown(
            f"EPSS {epss} ({row['epss_source']}). CVSS {cvss} ({row['cvss_source']}). "
            f"KEV {'yes' if row['in_kev'] else 'no'}."
        )
        if row["in_kev"]:
            triage = triage_label(str(row.get("triage") or "not_in_feed"))
            ransom = "Known" if row["ransomware"] else "Not known"
            st.markdown(f"Known ransomware use: **{ransom}**. forensicTriage: **{triage}**.")
            if row["forensics_required"]:
                st.markdown(FORENSIC_TRIAGE_NOTE)
                with st.expander("Forensic triage steps from the implementation guidance"):
                    for title, body in FORENSIC_TRIAGE_STEPS:
                        st.markdown(f"**{title}.** {body}")
            elif str(row.get("triage")) == "yes":
                st.markdown(
                    "The KEV catalog flags forensicTriage = Yes. The asset-level path does not, "
                    "because exposure and technical impact don't land on a 3-day forensics outcome. "
                    "Read the catalog notes before you skip triage."
                )
        owner = row.get("owner") or "Unassigned"
        unit = row.get("business_unit") or "Unassigned"
        exposed = "publicly exposed" if bool(row["exposed"]) else "internal"
        st.markdown(f"**{owner}** · {unit} · {exposed}")
        status = str(row.get("exception_status") or "")
        if status == "Active":
            st.markdown(
                f"SLA breach counting is **paused** until {row.get('exception_expiry')} "
                f"({row.get('exception_id')}, approved by {row.get('exception_approver')}). "
                f"Without the exception this row would be **{row.get('sla_status_raw')}**."
            )
            st.text(str(row.get("exception_justification") or ""))
            st.text(f"Compensating controls: {row.get('exception_controls') or ''}")
        elif status == "Expired":
            st.markdown(
                f"Exception **{row.get('exception_id')}** expired on {row.get('exception_expiry')}. "
                "The pause has ended, so this finding counts toward SLA breaches again."
            )
    if row.get("required_action"):
        with st.expander("CISA required action"):
            st.write(str(row["required_action"]))


def _queue_page(queue: pd.DataFrame, classic: bool) -> None:
    st.subheader("Fix queue")
    if queue.empty:
        st.info("Nothing in the queue matches these filters.")
        return
    st.caption(
        "Sorted by the KEV + EPSS + CVSS score. "
        "The decision path is the BOD 26-04 reason for the deadline."
        if not classic
        else "The path column is the older CISA SSVC decision. Deadlines on the other view stay on BOD 26-04."
    )
    shown = queue_frame(queue, classic=classic)
    event = st.dataframe(
        shown,
        hide_index=True,
        width="stretch",
        height=460,
        on_select="rerun",
        selection_mode="single-row",
        key="queue-table",
    )
    selected = list(getattr(getattr(event, "selection", None), "rows", []) or [])
    index = selected[0] if selected else 0
    _detail(queue.iloc[index], classic)
    st.download_button(
        "Download this queue as CSV",
        data=csv_download(queue),
        file_name="kev-radar-queue.csv",
        mime="text/csv",
    )


def _remediation_page(frame: pd.DataFrame, records: list) -> None:
    st.subheader("Remediation")
    forecast = breach_forecast(frame, AS_OF)
    st.markdown(forecast.statement)
    st.caption(
        f"Close rate uses fixes in the {forecast.history_days} days before {AS_OF.isoformat()} "
        f"({forecast.closed_in_history} fixed, {forecast.weekly_close_rate:.1f} per week). "
        "Fix-on-upgrade findings are outside the clock, so they are not in this projection. "
        "The overview's burn-down spends the same close rate on the overdue stock, so the two are alternatives."
    )
    _undated_open_caption(frame)
    aging = aging_buckets(frame, AS_OF)
    burn = burndown(frame, AS_OF)
    mix = outcome_mix(frame[frame["state"].map(is_open)] if not frame.empty else frame)
    left, right = st.columns(2)
    with left:
        st.markdown("**Aging of open findings**")
        fig = px.bar(aging, x="bucket", y="findings", color_discrete_sequence=["#e8a838"])
        fig.update_layout(showlegend=False, xaxis_title="", yaxis_title="Open findings")
        st.plotly_chart(_style(fig), width="stretch")
    with right:
        st.markdown("**Open findings, week by week**")
        fig = px.line(burn, x="week_ending", y="open_findings", markers=True, color_discrete_sequence=["#7eb6d9"])
        fig.update_layout(xaxis_title="", yaxis_title="Still open")
        st.plotly_chart(_style(fig), width="stretch")
    st.markdown("**Open findings by BOD 26-04 outcome**")
    if mix.empty:
        st.info("No open findings in this filter.")
    else:
        fig = px.bar(mix, x="findings", y="outcome", orientation="h", color_discrete_sequence=["#e08a4f"])
        fig.update_layout(yaxis_title="", xaxis_title="Open findings", yaxis={"categoryorder": "total ascending"})
        st.plotly_chart(_style(fig), width="stretch")
    st.markdown("**Average time to fix**")
    st.caption(
        "Mean days from first seen to last fixed, for findings already closed. "
        "The BOD clock can start earlier, when CISA added the CVE, and that is what the deadline uses."
    )
    by_sev, by_owner, by_unit = st.columns(3)
    tables = (
        (by_sev, "severity", "Severity"),
        (by_owner, "owner", "Owner"),
        (by_unit, "business_unit", "Business unit"),
    )
    for column, key, label in tables:
        summary = mean_time_to_fix(frame, key)
        with column:
            st.markdown(f"**{label}**")
            if summary.empty:
                st.caption("No closed findings in this filter.")
            else:
                summary = summary.rename(columns={key: label, "findings": "Fixed", "average_days": "Avg days"})
                st.dataframe(summary, hide_index=True, width="stretch")
    _exceptions_register(frame, records)


def _exceptions_register(frame: pd.DataFrame, records: list) -> None:
    st.subheader("Exceptions register")
    st.caption(
        "An active exception pauses SLA breach counting for that host and CVE through the expiry date. "
        "Expired exceptions are flagged and the finding counts as a breach again. "
        "The demo seed is rebuilt when the estate changes. Exceptions you add or import are written to "
        "`data/operator/exceptions.json` on this machine. That file is gitignored."
    )
    keys = set()
    if not frame.empty:
        keys = {finding_key(host, cve) for host, cve in zip(frame["host_name"], frame["cve"], strict=True)}
    table = exceptions_table(records, AS_OF)
    if table.empty:
        st.info("No exceptions yet. Add one for an open finding below. Uploads start with an empty register.")
    else:
        table = table.copy()
        table["In this filter"] = [
            "Yes" if finding_key(host, cve) in keys else "No"
            for host, cve in zip(table["Host"], table["CVE"], strict=True)
        ]
        st.dataframe(table, hide_index=True, width="stretch", height=280)
        csv_col, json_col = st.columns(2)
        csv_col.download_button(
            "Download register as CSV",
            data=exceptions_to_csv(records),
            file_name="kev-radar-exceptions.csv",
            mime="text/csv",
        )
        json_col.download_button(
            "Download register as JSON",
            data=exceptions_to_json(records),
            file_name="kev-radar-exceptions.json",
            mime="application/json",
        )
    imported = st.file_uploader(
        "Import exceptions",
        type=["csv", "json"],
        help="CSV or JSON using the download columns. Invalid rows are reported and skipped.",
    )
    if imported is not None:
        raw = imported.getvalue().decode("utf-8", errors="replace")
        digest = f"{imported.name}:{len(raw)}:{raw[:80]}"
        if st.session_state.get("exception_import_digest") != digest and st.button("Import this file"):
            if imported.name.lower().endswith(".json"):
                loaded, errors = exceptions_from_json(raw)
            else:
                loaded, errors = exceptions_from_csv(raw)
            loaded, cap_errors = enforce_import_limit(loaded)
            for message in [*errors, *cap_errors]:
                st.error(message)
            if loaded:
                existing = {item.get("exception_id") for item in st.session_state.get("exception_extra") or []}
                existing.update(item.get("exception_id") for item in st.session_state.get("exception_seed") or [])
                added = 0
                for record in loaded:
                    if record.exception_id in existing:
                        continue
                    st.session_state.setdefault("exception_extra", []).append(record.to_dict())
                    existing.add(record.exception_id)
                    added += 1
                st.session_state["exception_import_digest"] = digest
                _persist_exceptions()
                if added:
                    st.success(f"Imported {added} exception{'s' if added != 1 else ''}.")
                    st.rerun()
                else:
                    st.info("Every row in that file is already in the register.")
    open_rows = frame[frame["state"].map(is_open)] if not frame.empty else frame
    if open_rows.empty:
        st.caption("There is no open finding in this filter to attach an exception to.")
    else:
        options = open_rows.reset_index(drop=True)
        labels = [f"{row.cve} on {row.host_name}" for row in options.itertuples(index=False)]
        with st.form("add-exception"):
            choice = st.selectbox("Finding", labels)
            owner = st.text_input("Owner", help="Leave blank to use the finding's owner.")
            justification = st.text_area("Justification")
            controls = st.text_area("Compensating controls")
            expiry = st.date_input("Expiry", value=AS_OF + timedelta(days=30))
            approver = st.text_input("Approver")
            submitted = st.form_submit_button("Add exception")
        if submitted:
            picked = options.iloc[labels.index(choice)]
            chosen_owner = owner.strip() or str(picked["owner"] or "Unassigned")
            try:
                st.session_state["exception_seq"] = int(st.session_state.get("exception_seq", 0)) + 1
                record = RiskException(
                    exception_id=f"EX-USER-{st.session_state['exception_seq']:02d}",
                    host_name=str(picked["host_name"]),
                    cve=str(picked["cve"]).upper(),
                    owner=chosen_owner,
                    justification=justification,
                    compensating_controls=controls,
                    expiry=expiry,
                    approver=approver,
                )
            except ValueError as exc:
                st.error(str(exc))
            else:
                active = [
                    item
                    for item in records
                    if item.pauses(AS_OF) and finding_key(item.host_name, item.cve) == finding_key(record.host_name, record.cve)
                ]
                if active:
                    st.error(f"{record.cve} on {record.host_name} already has active exception {active[0].exception_id}.")
                else:
                    st.session_state.setdefault("exception_extra", []).append(record.to_dict())
                    _persist_exceptions()
                    st.rerun()
    if records:
        removal = st.selectbox("Remove from this session", ["—", *[record.exception_id for record in records]])
        if st.button("Remove exception") and removal != "—":
            st.session_state.setdefault("exception_removed", []).append(removal)
            _persist_exceptions()
            st.rerun()


def _week_page(frame: pd.DataFrame, catalog: dict, previous: dict | None, version: str) -> None:
    st.subheader("KEV this week")
    current = catalog.get("vulnerabilities", [])
    previous_rows = previous.get("vulnerabilities", []) if previous else None
    report = kev_this_week(current, previous_rows, _estate_hits(frame), AS_OF)
    week = report["this_week"]
    hits = [item for item in week if item.in_estate]
    ransomware_hits = [item for item in hits if item.ransomware]
    triage_hits = [item for item in hits if item.triage == "yes"]
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Added in 7 days", f"{len(week):,}")
    c2.metric("Hitting this estate", f"{len(hits):,}")
    c3.metric("Ransomware, in estate", f"{len(ransomware_hits):,}")
    c4.metric("forensicTriage Yes, in estate", f"{len(triage_hits):,}")
    estate_ransom = 0
    if not frame.empty:
        estate_ransom = int((frame["ransomware"].map(bool) & frame["state"].map(is_open)).sum())
    st.caption(
        f"Window {(AS_OF - timedelta(days=6)).isoformat()} through {AS_OF.isoformat()}, using dateAdded. "
        "A hit means an open finding on the synthetic estate. "
        "If a feed omits forensicTriage, the row says so instead of failing. "
        f"Open findings in this filter with known ransomware use, including older KEV entries: {estate_ransom:,}."
    )
    if not week:
        st.info("The catalog has no KEV additions in this 7-day window.")
    else:
        rows = []
        for item in week:
            rows.append(
                {
                    "CVE": item.cve,
                    "Added": item.date_added.isoformat() if item.date_added else "",
                    "KEV due": item.due_date.isoformat() if item.due_date else "",
                    "Vendor": item.vendor,
                    "Product": item.product,
                    "Name": item.name,
                    "In estate": "Yes" if item.in_estate else "No",
                    "Open hosts": item.host_count,
                    "Exposed hosts": item.exposed_host_count,
                    "Ransomware": "Known" if item.ransomware else "Not known",
                    "forensicTriage": triage_label(item.triage),
                }
            )
        table = pd.DataFrame(rows)
        st.dataframe(table, hide_index=True, width="stretch", height=420)
        choice = st.selectbox("Hosts for a new KEV", [item.cve for item in week if item.in_estate] or ["—"])
        chosen = next((item for item in week if item.cve == choice), None)
        if chosen and chosen.hits:
            st.markdown(f"**{chosen.cve}** — {chosen.name}")
            host_frame = pd.DataFrame(
                [
                    {
                        "Host": hit.host_name,
                        "Owner": hit.owner,
                        "Business unit": hit.business_unit,
                        "Exposed": "Yes" if hit.exposed else "No",
                        "State": hit.state,
                    }
                    for hit in chosen.hits
                ]
            )
            st.dataframe(host_frame, hide_index=True, width="stretch")
    if report["snapshot_only"]:
        with st.expander(f"{len(report['snapshot_only'])} more CVEs are new since the previous snapshot, outside this 7-day window"):
            st.write(", ".join(item.cve for item in report["snapshot_only"][:40]))
    estate_name, synthetic = _estate_label()
    markdown = render_monday_report(
        catalog_version=version, as_of=AS_OF, items=week, estate_name=estate_name, synthetic=synthetic
    )
    st.download_button(
        "Download KEV Monday briefing",
        data=markdown,
        file_name=f"kev-monday-{AS_OF.isoformat()}.md",
        mime="text/markdown",
    )


def _signals_page(frame: pd.DataFrame, catalog: dict) -> None:
    st.subheader("Signals")
    open_kev = frame[frame["in_kev"].map(bool) & frame["state"].map(is_open)] if not frame.empty else frame
    if not open_kev.empty:
        low_cvss = open_kev[open_kev["cvss"].fillna(10) < 7]
        st.markdown(
            f"**{len(low_cvss)}** open KEV findings in this filter have a CVSS base under 7. "
            "A queue sorted only by CVSS would bury them under high-scoring bugs nobody is exploiting."
        )
    left, right = st.columns(2)
    with left:
        st.markdown("**EPSS versus CVSS, CVEs in this filter**")
        points = scatter_frame(frame)
        if points.empty:
            st.info("No CVEs in this filter have both an EPSS score and a CVSS score.")
        else:
            fig = px.scatter(
                points,
                x="cvss",
                y="epss_percent",
                color="kev",
                size="hosts",
                hover_name="cve",
                hover_data={"name": True, "hosts": True, "epss_percent": ":.1f"},
                color_discrete_map={"In KEV": "#e8a838", "Not in KEV": "#7eb6d9"},
            )
            fig.update_layout(xaxis_title="CVSS base", yaxis_title="EPSS %", xaxis_range=[0, 10])
            st.plotly_chart(_style(fig), width="stretch")
    with right:
        st.markdown("**Open KEV findings by vendor**")
        vendors = vendor_frame(frame)
        if vendors.empty:
            st.info("No open KEV findings in this filter.")
        else:
            fig = px.bar(vendors, x="findings", y="vendor", orientation="h", color_discrete_sequence=["#e8a838"])
            fig.update_layout(yaxis_title="", xaxis_title="Open findings", yaxis={"categoryorder": "total ascending"})
            st.plotly_chart(_style(fig), width="stretch")
    st.markdown("**KEV catalog additions**")
    additions = kev_additions_by_month(catalog.get("vulnerabilities", []))
    fig = px.bar(additions, x="month", y="additions", color_discrete_sequence=["#7eb6d9"])
    fig.update_layout(xaxis_title="", yaxis_title="CVEs added")
    st.plotly_chart(_style(fig), width="stretch")
    with st.expander("How a score is built"):
        st.markdown(
            """
The sort score is a weighted sum, capped at 100:

- **35** if the CVE is in CISA KEV
- **10** if that KEV entry's `knownRansomwareCampaignUse` is Known
- **up to 25** from FIRST EPSS (probability × 25)
- **up to 20** from CVSS base (score / 10 × 20)
- **10** if the asset is publicly exposed

Missing EPSS or CVSS adds zero and the row says so. Bands are labels only: Critical ≥ 70, High ≥ 40, Medium ≥ 15, Low below that.

The **deadline is not the score**. It comes from the BOD 26-04 table: In KEV, publicly exposed, Automatable, Technical Impact. Automatable and Technical Impact are CISA Vulnrichment SSVC fields. Exposure comes from the asset tag, or from CISA's fallback (public address, then asset type `network`, then, for a KEV, generally public-facing software, otherwise internal).
            """
        )


def _undated_open_caption(frame: pd.DataFrame) -> None:
    """Time charts place a finding by its first-seen date; say how many have none."""
    if frame.empty or "first_observed" not in frame.columns:
        return
    undated = int((frame["state"].map(is_open) & frame["first_observed"].isna()).sum())
    if undated:
        noun = "finding has" if undated == 1 else "findings have"
        st.caption(
            f"{undated} open {noun} no first-seen date in this export, so the charts on this page leave "
            "them out. The cards above still count them."
        )


def _estate_label() -> tuple[str, bool]:
    """The name every export uses for the current source, and whether it is synthetic."""
    return st.session_state.get("estate_label", ("Harborline Mutual lab", True))


def _persist_exceptions() -> None:
    if not operator_file_enabled():
        return
    save_operator_register(
        {
            "extra": list(st.session_state.get("exception_extra") or []),
            "removed": list(st.session_state.get("exception_removed") or []),
            "seq": int(st.session_state.get("exception_seq") or 0),
        }
    )


def _estate_exceptions(mode: str, seed: int, upload, frame: pd.DataFrame) -> list:
    """Demo seed plus this visitor's register. It is shared through a file only when the operator flag is set."""
    if frame.empty:
        fingerprint = "empty"
    else:
        fingerprint = f"{len(frame)}:{frame.iloc[0]['cve']}:{frame.iloc[-1]['host_name']}"
    name = getattr(upload, "name", "") if upload is not None else ""
    token = f"{mode}:{seed}:{name}:{fingerprint}"
    if st.session_state.get("exception_token") != token:
        st.session_state["exception_token"] = token
        seeded = [] if mode == "Upload CSV" else [record.to_dict() for record in seed_exceptions(frame, AS_OF)]
        stored = load_operator_register() if operator_file_enabled() else {"extra": [], "removed": [], "seq": 0}
        st.session_state["exception_seed"] = seeded
        st.session_state["exception_extra"] = list(stored["extra"])
        st.session_state["exception_removed"] = list(stored["removed"])
        st.session_state["exception_seq"] = int(stored["seq"])
    removed = set(st.session_state.get("exception_removed") or [])
    records = []
    for payload in list(st.session_state.get("exception_seed") or []) + list(st.session_state.get("exception_extra") or []):
        if payload.get("exception_id") in removed:
            continue
        records.append(record_from_dict(payload))
    return records


def _merged_msrc(snapshot: dict) -> dict:
    merged = dict((snapshot or {}).get("cves") or {})
    extra = st.session_state.get("msrc_extra") or {}
    for cve, entry in extra.items():
        merged.setdefault(str(cve).upper(), entry)
    return {"cves": merged, "fetched_at": (snapshot or {}).get("fetched_at", "")}


def _windows_page(frame: pd.DataFrame, snapshot: dict) -> None:
    st.subheader("Windows patches")
    kb_map = _merged_msrc(snapshot)
    fetched = kb_map.get("fetched_at") or "not fetched"
    st.caption(
        f"KB articles come from the MSRC CVRF API, cached in the offline snapshot ({fetched}). "
        "A CVE missing from that file can be looked up live. If the call fails, the snapshot is what remains. "
        "The PowerShell audit only reads installed hotfixes. It does not install, remove, or change anything."
    )
    if frame.empty:
        st.info("No findings in this filter.")
        return
    known = set(kb_map["cves"])

    def _keep(row: pd.Series) -> bool:
        if str(row.get("cve") or "").upper() in known:
            return True
        return is_windows_text(row.get("kev_vendor"), row.get("kev_product"), row.get("vuln_name"), row.get("plugin_name"))

    windows = frame[frame.apply(_keep, axis=1)]
    if windows.empty:
        st.info("No Microsoft or Windows findings in this filter, and the MSRC snapshot has no matching CVE.")
        return
    summary_rows = []
    script_rows = []
    hosts: list[str] = []
    missing: list[str] = []
    for cve, group in windows.groupby(windows["cve"].astype(str).str.upper()):
        patches = patches_for(kb_map, cve)
        entry = kb_map["cves"].get(cve) or {}
        if cve not in known:
            missing.append(cve)
        open_group = group[group["state"].map(is_open)]
        host_names = sorted({str(host) for host in open_group["host_name"].tolist()})
        hosts.extend(host_names)
        products = ""
        builds = ""
        if patches:
            products = "; ".join(patches[0].get("products") or [])
            builds = ", ".join(patches[0].get("fixed_builds") or [])
            for patch in patches:
                script_rows.append(
                    {
                        "cve": cve,
                        "kb": patch["kb"],
                        "products": patch.get("products") or [],
                        "fixed_builds": patch.get("fixed_builds") or [],
                    }
                )
        summary_rows.append(
            {
                "CVE": cve,
                "Open hosts": len(host_names),
                "KB articles": ", ".join(patch["kb"] for patch in patches) or "—",
                "Sample products": products or "—",
                "Fixed build": builds or "—",
                "Restart": (patches[0].get("restart") if patches else "") or "—",
                "Source": entry.get("document_id") or entry.get("note") or "Not in the snapshot",
            }
        )
    summary = pd.DataFrame(summary_rows).sort_values(["Open hosts", "CVE"], ascending=[False, True])
    st.dataframe(summary, hide_index=True, width="stretch", height=360)
    if missing:
        label = f"Look up {min(15, len(missing))} CVEs missing from the snapshot"
        if st.button(label):
            extra = dict(st.session_state.get("msrc_extra") or {})
            failed = []
            for cve in missing[:15]:
                try:
                    extra[cve] = cached_msrc_cve(cve)
                except Exception:
                    failed.append(cve)
            st.session_state["msrc_extra"] = extra
            if failed:
                st.warning(
                    "MSRC did not answer for "
                    + ", ".join(failed)
                    + ". Those CVEs stay on the snapshot fallback, which has no article for them."
                )
            st.rerun()
    try:
        script = render_audit_script(script_rows, hosts=sorted(set(hosts)))
    except RuntimeError as exc:
        st.error(str(exc))
        script = ""
    if script:
        st.download_button(
            "Download read-only PowerShell audit",
            data=script,
            file_name="kev-radar-hotfix-audit.ps1",
            mime="text/plain",
        )
        with st.expander("Preview the audit script"):
            st.code(script, language="powershell")


def _show_checked_briefing(markdown: str, result, file_name: str) -> None:
    if result.passed:
        st.success("Fact check passed. Every CVE, hostname, and number in this note is in the briefing input.")
    else:
        st.error("Fact check rejected this note.")
        for item in result.violations:
            st.write(item)
        return
    st.markdown(markdown)
    st.download_button(
        "Download briefing",
        data=markdown,
        file_name=file_name,
        mime="text/markdown",
        key=f"download-{file_name}",
    )


def _briefing_page(frame: pd.DataFrame, stats: dict, records: list) -> None:
    st.subheader("Briefing")
    st.caption(
        "Offline template mode is the default and needs no key. "
        "A live model runs only when you supply your own API key for this session. "
        "The key is not written to the repo. The checker rejects any CVE, hostname, or number that is not in the queue data."
    )
    facts = build_facts(frame, stats, records, AS_OF.isoformat(), estate=_estate_label()[0])
    offline = render_offline(facts)
    offline_check = check_text(offline["markdown"], facts)
    writer = st.radio(
        "Writer",
        ["Offline template (default)", "Live model (your key)"],
        horizontal=True,
    )
    if writer == "Live model (your key)":
        settings = resolve_llm_settings()
        typed = st.text_input(
            "API key",
            type="password",
            help="Your own key, sent as a Bearer token on this request only. It is never stored, and the app has no key of its own.",
        )
        model = st.text_input("Model", value=settings["model"])
        st.caption(f"Endpoint: {settings['base_url']} (set by the app's configuration, not on this page).")
        if st.button("Write with the live model"):
            call = resolve_llm_settings(api_key=typed, model=model)
            if not call["api_key"]:
                st.error("Paste your own API key to use the live model. The offline template below is still the briefing.")
            else:
                try:
                    draft = complete_live(facts, api_key=call["api_key"], base_url=call["base_url"], model=call["model"])
                except Exception as exc:
                    st.error(f"The live call failed ({type(exc).__name__}). The offline template is unchanged.")
                else:
                    live_check = check_text(draft, facts)
                    if live_check.passed:
                        st.success("Fact check passed on the live draft.")
                        st.markdown(draft)
                    else:
                        st.error("Fact check rejected the live draft. It is not the briefing.")
                        for item in live_check.violations:
                            st.write(f"- {item}")
                        with st.expander("Rejected draft"):
                            st.code(draft)
        st.markdown("**Offline template, checked**")
    _show_checked_briefing(offline["markdown"], offline_check, f"kev-radar-briefing-{AS_OF.isoformat()}.md")


def _overview_page(frame: pd.DataFrame, stats: dict) -> None:
    st.subheader("Executive overview")
    st.caption(
        "The cards above are this filter. The charts are the last eight weeks of the same rows. "
        "Earlier weeks do not replay exceptions; the latest overdue point does, so it matches the card."
    )
    if frame.empty:
        st.info("No findings in this filter. Load the bundled estate or clear a filter.")
        return
    numbers = headline(frame, AS_OF)
    trend = risk_trend(frame, AS_OF)
    _undated_open_caption(frame)
    left, right = st.columns(2)
    with left:
        st.markdown("**Open risk score**")
        st.caption("Sum of priority scores on findings that were still open at each week ending.")
        fig = px.line(trend, x="week_ending", y="risk_score", markers=True, color_discrete_sequence=["#e0a33a"])
        fig.update_layout(height=220, xaxis_title="", yaxis_title="Risk score")
        st.plotly_chart(_style(fig), width="stretch")
    with right:
        st.markdown("**Overdue findings**")
        st.caption("Open and past the BOD deadline. The last point excludes today's active exceptions.")
        fig = px.area(trend, x="week_ending", y="overdue", color_discrete_sequence=["#d26a4a"])
        fig.update_layout(height=220, xaxis_title="", yaxis_title="Overdue")
        st.plotly_chart(_style(fig), width="stretch")
    st.markdown("**Overdue burn-down against the recent close rate**")
    st.caption(
        "Bars are the overdue stock. The dashed line holds that stock flat except for the last four weeks' "
        "close rate, projected four weeks ahead. Findings that will become newly overdue are not in the line. "
        "The 7-day miss projection on the Remediation page uses the same close rate, so read the two as "
        "alternative uses of one team's capacity, not as projections that add up."
    )
    burn = projected_burndown(numbers["overdue"], numbers["weekly_close_rate"], AS_OF)
    past = trend[["week_ending", "overdue"]].rename(columns={"overdue": "count"})
    past["series"] = "Overdue"
    future = burn.rename(columns={"overdue": "count"})
    future["series"] = "If the close rate holds"
    fig = go.Figure()
    fig.add_bar(
        x=past["week_ending"],
        y=past["count"],
        name="Overdue",
        marker_color="#7eb6d9",
    )
    fig.add_scatter(
        x=future["week_ending"],
        y=future["count"],
        name="If the close rate holds",
        mode="lines+markers",
        line={"color": "#e0a33a", "dash": "dash"},
    )
    fig.update_layout(height=300, xaxis_title="", yaxis_title="Findings", legend_title="", barmode="overlay")
    st.plotly_chart(_style(fig), width="stretch")
    st.markdown("**Top 10 to fix this week**")
    st.caption("Overdue first, then due within 7 days, then the highest score. Active exceptions are left off this list.")
    top = top_to_fix(frame, AS_OF, limit=10)
    if top.empty:
        st.info("Nothing open is waiting on a patch in this filter.")
    else:
        shown = top.rename(
            columns={
                "host_name": "Host",
                "cve": "CVE",
                "owner": "Owner",
                "business_unit": "Business unit",
                "score": "Score",
                "sla_status": "SLA",
                "reason": "Why this week",
            }
        )
        st.dataframe(
            shown[["CVE", "Host", "Owner", "Business unit", "SLA", "Score", "Why this week"]],
            hide_index=True,
            width="stretch",
        )
    _export_bar(frame, stats, top)


def _export_bar(frame: pd.DataFrame, stats: dict, top: pd.DataFrame) -> None:
    st.markdown("**Take this with you**")
    estate_name, synthetic = _estate_label()
    html_report = render_html_report(
        frame, stats, top if not top.empty else pd.DataFrame(), AS_OF, estate=estate_name, synthetic=synthetic
    )
    tickets = render_tickets(frame, AS_OF)
    csv_text = csv_download(frame)
    one, two, three = st.columns(3)
    one.download_button(
        "Board packet (HTML)",
        data=html_report,
        file_name=f"kev-radar-board-{AS_OF.isoformat()}.html",
        mime="text/html",
        help="Print this file to PDF from the browser. It is a status report, not a forecast model.",
    )
    two.download_button(
        "Tickets (Markdown)",
        data=tickets,
        file_name=f"kev-radar-tickets-{AS_OF.isoformat()}.md",
        mime="text/markdown",
        help="One GitHub or Jira issue per open finding, using only figures from this queue.",
    )
    three.download_button(
        "Findings (CSV)",
        data=csv_text,
        file_name=f"kev-radar-findings-{AS_OF.isoformat()}.csv",
        mime="text/csv",
    )


def _surface_page(frame: pd.DataFrame) -> None:
    st.subheader("Attack surface")
    st.caption(
        "Each cell is open findings in that business unit. Color is mean EPSS. "
        "The four lanes are mutually exclusive: exposure crossed with KEV membership. "
        "An empty cell is zero findings, not a zero exploit probability."
    )
    if frame.empty:
        st.info("No findings in this filter.")
        return
    summary = exposure_heatmap(frame)
    units, lanes, z, text = heatmap_matrix(summary)
    if not units:
        st.info("No open findings in this filter.")
    else:
        fig = go.Figure(
            data=go.Heatmap(
                z=z,
                x=lanes,
                y=units,
                text=text,
                texttemplate="%{text}",
                colorscale=[[0.0, "#1a2733"], [0.45, "#c47b2b"], [1.0, "#f0c14a"]],
                colorbar={"title": "Mean EPSS"},
                hovertemplate="%{y}<br>%{x}<br>mean EPSS %{z:.2f}<br>open %{text}<extra></extra>",
            )
        )
        fig.update_layout(height=420, xaxis_title="", yaxis_title="")
        st.plotly_chart(_style(fig), width="stretch")
    st.markdown("**Asset drill-down**")
    index = host_index(frame)
    if index.empty:
        st.info("No hosts in this filter.")
        return
    labels = [
        f"{row.host_name} · {row.open_findings} open · score {row.max_score}"
        for row in index.itertuples(index=False)
    ]
    choice = st.selectbox("Host", labels)
    host = index.iloc[labels.index(choice)]
    exposed = "publicly exposed" if bool(host["exposed"]) else "internal"
    st.markdown(
        f"**{host['host_name']}** · {host['owner']} · {host['business_unit']} · {exposed}. "
        f"{int(host['open_findings'])} open, {int(host['overdue'])} overdue."
    )
    detail = host_findings(frame, str(host["host_name"]))
    if detail.empty:
        st.info("This host has no findings in the filter.")
        return
    shown = pd.DataFrame(
        {
            "CVE": detail["cve"],
            "State": detail["state"],
            "SLA": detail["sla_status"],
            "Score": detail["score"].round(1),
            "Deadline": detail["deadline"].map(lambda value: "—" if value is None or pd.isna(value) else str(value)[:10]),
            "Decision path": detail["decision_path"],
        }
    )
    st.dataframe(shown, hide_index=True, width="stretch", height=360)
    path_labels = [f"{row.cve} · {row.state} · {row.sla_status}" for row in detail.itertuples(index=False)]
    pick = st.selectbox("Decision path", path_labels)
    row = detail.iloc[path_labels.index(pick)]
    st.markdown(f'<div class="path">{html.escape(str(row["decision_path"]))}</div>', unsafe_allow_html=True)
    st.caption(str(row.get("clock_reason") or ""))
    if row.get("assumption_notes"):
        st.caption(str(row["assumption_notes"]))


def _what_if_page(frame: pd.DataFrame, msrc: dict) -> None:
    st.subheader("What if we patch this")
    st.caption(
        "Pick open findings, a CVE, or a Microsoft KB. The preview removes those open rows from the backlog. "
        "It does not add them to the last four weeks of closes, so the close rate stays the rate you have already demonstrated. "
        "The miss count is still a projection."
    )
    if frame.empty:
        st.info("No findings in this filter.")
        return
    open_rows = frame[frame["state"].map(is_open)].reset_index(drop=True)
    if open_rows.empty:
        st.info("Nothing open in this filter, so there is nothing to patch.")
        return
    options = open_rows.head(40)
    labels = [f"{row.cve} on {row.host_name}" for row in options.itertuples(index=False)]
    chosen = st.multiselect("Findings", labels, help="The first 40 open rows in the current sort. A CVE below covers every open instance.")
    cve_text = st.text_input("Or CVE IDs, comma separated")
    kb_text = st.text_input("Or a KB article", help="Matched against the MSRC snapshot. KB3154070 and 3154070 are the same article.")
    kb_cves = cves_addressed_by_kb(msrc, kb_text) if kb_text.strip() else []
    if kb_text.strip():
        if kb_cves:
            st.caption(f"{kb_text.strip()} maps to {', '.join(kb_cves)}.")
        else:
            st.warning("That KB is not in the MSRC snapshot, so it does not select any findings.")
    pairs = []
    for label in chosen:
        cve, _, host = label.partition(" on ")
        pairs.append((host, cve))
    extra_cves = [part.strip() for part in cve_text.split(",") if part.strip()]
    keys = select_open_keys(frame, cves=[*extra_cves, *kb_cves], pairs=pairs)
    result = simulate(frame, AS_OF, keys)
    if not keys:
        st.info("Select at least one finding, CVE, or known KB to see the change.")
        return
    st.markdown(
        f"**{result.patched}** open finding{'s' if result.patched != 1 else ''} across "
        f"**{result.hosts}** host{'s' if result.hosts != 1 else ''} and "
        f"**{len(result.cves)}** CVE{'s' if len(result.cves) != 1 else ''}."
    )
    cols = st.columns(3)
    cols[0].metric(
        "Overdue",
        f"{result.after_overdue:,}",
        delta=f"{result.after_overdue - result.before_overdue:,}",
        delta_color="inverse",
        help="Open findings past the deadline after the selected rows are removed.",
    )
    cols[1].metric(
        "Portfolio risk",
        f"{result.after_risk:,.0f}",
        delta=f"{result.after_risk - result.before_risk:,.0f}",
        delta_color="inverse",
        help="Sum of priority scores on the findings that would remain open.",
    )
    cols[2].metric(
        "Projected misses",
        f"{result.after_misses:,}",
        delta=f"{result.after_misses - result.before_misses:,}",
        delta_color="inverse",
        help="The 7-day breach sketch after the removal. The close rate is unchanged.",
    )
    st.markdown(result.after_statement)


def _about_page(meta: dict, enrich_report: dict) -> None:
    st.subheader("About this console")
    st.markdown(
        "KEV Radar is a remediation-ops console. "
        "Harborline Mutual is fictional. The CVE identifiers and the feeds are public. "
        "Nothing here is an employer export."
    )
    st.markdown("**Sources for the deadline engine**")
    st.markdown(
        f"- [BOD 26-04]({DIRECTIVE_URL}), June 10, 2026. "
        "Table 1 starts when either CISA adds the CVE to KEV or the agency enumerates it on an asset, whichever is first. "
        "“& forensic triage” means remediate within three days and assess whether the asset was compromised. "
        "“Fix on system upgrade” means the next scheduled major upgrade or rebuild."
    )
    st.markdown(
        f"- [Implementation guidance]({GUIDANCE_URL}), issued June 10, 2026 and updated August 25, 2026. "
        "Missing Automatable is treated as No. Missing Technical Impact is treated as Total. "
        "Exposure falls through a public address, then asset type `network`, then — for a KEV — software CISA's analysis treats as generally public-facing, then internal."
    )
    st.markdown(
        f"- [CERT/CC response table]({CERT_TABLE_URL}), model `cisa:BOD2604:1.0.0`, all 16 rows. "
        "The directive points at the Vulnrichment definitions maintained with CERT/CC SSVC."
    )
    st.markdown(
        f"- [cisagov/vulnrichment]({VULNRICHMENT_REPO}) for SSVC fields that are not in the local snapshot. "
        "A 404 keeps the missing-data fallback and marks the row assumed."
    )
    st.info(
        "CISA has not published the product list behind the generally-public-facing step. "
        "When an asset has no exposure tag, no public address, and is not type network, "
        "KEV Radar matches a short edge-software list (VPN, firewall, PAN-OS, and similar) and labels that exposure assumed. "
        "An Internet Exposed tag, including an explicit No, always wins."
    )
    st.markdown(FORENSIC_TRIAGE_NOTE)
    with st.expander("The six forensic-triage steps"):
        for title, body in FORENSIC_TRIAGE_STEPS:
            st.markdown(f"**{title}.** {body}")
    fetched = len(enrich_report.get("fetched") or [])
    missing = len(enrich_report.get("not_published") or [])
    failed = len(enrich_report.get("failed") or [])
    skipped = len(enrich_report.get("skipped") or [])
    st.caption(
        f"Snapshot fetched {meta.get('fetched_at', '—')}. "
        f"Vulnrichment rows in the snapshot: {meta.get('vulnrichment_count', '—')}. "
        f"Live enrichment this session: {fetched} fetched, {missing} not published, {failed} failed, {skipped} left for a later pass."
    )


def main() -> None:
    try:
        bundle = cached_bundle()
    except FileNotFoundError:
        st.error(
            "The offline snapshot is missing. From the repo root run "
            "`python scripts/refresh_snapshots.py`, then reload."
        )
        return

    catalog, feed_label = _catalog_from(bundle)
    meta = bundle.get("metadata") or {}
    version = str(catalog.get("catalogVersion") or meta.get("kev_catalog_version") or "")

    st.markdown(
        f"""
        <div class="banner">
          <p class="kicker">Remediation operations · BOD 26-04</p>
          <h1>KEV Radar</h1>
          <p>What is due, who owns it, and whether the fix will miss its SLA.
          Harborline Mutual is a fictional estate. CVE IDs and the feeds are public.
          No scanner login, no employer data.</p>
          <p class="note">KEV source: {html.escape(feed_label)}.
          EPSS date {html.escape(str(bundle.get('epss_date') or 'snapshot'))}.
          Vulnrichment rows in the snapshot: {meta.get('vulnrichment_count', '—')}.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.sidebar:
        st.header("Estate")
        requested = st.query_params.get("page", "Overview")
        if isinstance(requested, (list, tuple)):
            requested = requested[0] if requested else "Overview"
        if requested not in PAGES:
            requested = "Overview"
        if "page" not in st.session_state:
            st.session_state["page"] = requested
        page = st.radio("Page", PAGES, key="page")
        st.query_params["page"] = page
        mode = st.radio(
            "Source",
            ["Bundled demo", "Upload CSV", "Regenerate"],
            label_visibility="collapsed",
        )
        upload = None
        seed = DEMO_SEED
        if mode == "Upload CSV":
            upload = st.file_uploader("Tenable findings CSV", type=["csv"])
            st.caption("Use the Vulnerability Management findings export. Nessus-style headers work too.")
        elif mode == "Regenerate":
            seed = int(st.number_input("Seed", min_value=1, max_value=999999, value=DEMO_SEED, step=1))
            st.caption("Same generator as the bundled file. Seed 2604 rebuilds that estate.")
        st.header("Filter")
        # Filters are filled after the frame exists; widgets are declared later.
        filter_slot = st.container()
        st.header("Decision view")
        classic = st.toggle("Classic CISA SSVC", value=False, help="Show Track / Track* / Attend / Act beside the BOD 26-04 deadline.")
        mission = st.selectbox("Mission & well-being", ["medium", "low", "high"], index=0)
        include_fixed = st.toggle("Include fixed in the queue", value=False)
        st.caption(
            "BOD 26-04 replaced BOD 22-01 on June 10, 2026. "
            "The clock starts on the earlier of KEV addition and first seen. "
            "Active exceptions pause breach counting."
        )

    st.session_state["estate_label"] = (
        ("Uploaded export", False) if mode == "Upload CSV" else ("Harborline Mutual lab", True)
    )

    if mode == "Upload CSV" and upload is None:
        st.info(
            "Upload a Tenable Vulnerability Management findings CSV, or switch the sidebar back to the bundled demo. "
            "Expected columns include `definition.cve` and `asset.host_name` (or the older Nessus `CVE` and `Host` headers). "
            "Owner, business unit, and internet exposure are read from `asset.tags` when those columns are absent."
        )
        return

    try:
        parsed = _load_estate(mode, upload, seed, version)
    except ParseError as exc:
        st.error(str(exc))
        return
    except FileNotFoundError:
        st.error("The bundled demo CSV is missing. Run `python scripts/refresh_snapshots.py`.")
        return
    if parsed is None:
        return

    for warning in parsed.warnings:
        st.warning(warning)

    kev_by_id = {
        str(entry.get("cveID", "")).upper(): entry
        for entry in catalog.get("vulnerabilities", [])
        if entry.get("cveID")
    }
    cves = [] if parsed.findings.empty else parsed.findings["cve"].astype(str).str.upper().tolist()
    epss = _merge_epss(bundle["epss"], cves)
    ssvc, enrich_report = _live_ssvc(bundle["ssvc"], cves)
    frame = prioritize(
        parsed.findings,
        kev_by_id,
        epss,
        ssvc,
        AS_OF,
        mission=mission,
    )
    records = _estate_exceptions(mode, seed, upload, frame)

    with filter_slot:
        units = sorted(frame["business_unit"].dropna().unique()) if not frame.empty else []
        owners = sorted(frame["owner"].dropna().unique()) if not frame.empty else []
        chosen_units = st.multiselect("Business unit", units)
        chosen_owners = st.multiselect("Owner", owners)
        exposure = st.selectbox("Exposure", ["Any", "Publicly exposed", "Internal"])
        kev_only = st.checkbox("KEV only")
        ransomware_only = st.checkbox("Known ransomware use")
        query = st.text_input("Search host, CVE, or owner")

    scoped = apply_exceptions(
        _apply_scope(
            frame,
            units=chosen_units,
            owners=chosen_owners,
            exposure=exposure,
            kev_only=kev_only,
            ransomware_only=ransomware_only,
            query=query,
        ),
        records,
        AS_OF,
    )
    visible_records = [
        record
        for record in records
        if finding_key(record.host_name, record.cve)
        in set(finding_key(host, cve) for host, cve in zip(scoped["host_name"], scoped["cve"], strict=False))
    ] if not scoped.empty else []
    stats = _metrics(scoped)
    _show_metrics(stats)
    assumed = 0
    exposure_assumed = 0
    if not scoped.empty:
        assumed_mask = scoped["automatable_assumed"].map(bool) | scoped["technical_impact_assumed"].map(bool)
        assumed = int(assumed_mask.sum())
        if "exposure_assumed" in scoped.columns:
            exposure_assumed = int(scoped["exposure_assumed"].map(bool).sum())
    st.caption(
        f"{parsed.raw_rows:,} export rows collapsed to {parsed.collapsed_findings:,} host + CVE findings. "
        f"Showing {len(scoped):,} after filters. "
        f"{assumed:,} use an assumed Automatable or Technical Impact value. "
        f"{exposure_assumed:,} use an assumed public-facing exposure."
    )
    if enrich_report.get("failed"):
        st.warning(
            "Vulnrichment could not be read for "
            f"{len(enrich_report['failed'])} CVE(s). Those rows use the missing-data fallback until the next reload."
        )

    queue = scoped if include_fixed else scoped[scoped["state"].isin(list(OPEN))]
    queue = queue.reset_index(drop=True)
    scoped = scoped.reset_index(drop=True)

    if page == "Overview":
        _overview_page(scoped, stats)
    elif page == "Attack surface":
        _surface_page(scoped)
    elif page == "What-if":
        _what_if_page(scoped, bundle.get("msrc") or {})
    elif page == "Remediation":
        _remediation_page(scoped, records)
    elif page == "KEV this week":
        _week_page(scoped, catalog, bundle.get("previous"), version)
    elif page == "Windows patches":
        _windows_page(scoped, bundle.get("msrc") or {})
    elif page == "Briefing":
        _briefing_page(scoped, stats, visible_records)
    elif page == "Signals":
        _signals_page(scoped, catalog)
    elif page == "About":
        _about_page(meta, enrich_report)
    else:
        _queue_page(queue, classic)


if __name__ == "__main__":
    main()
