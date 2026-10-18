"""Board packet (print-ready HTML) and GitHub/Jira-ready Markdown tickets.

Both writers use only fields already on the findings frame. They do not
call a model and they do not invent counts.
"""

from __future__ import annotations

import html
from datetime import date

import pandas as pd

from kev_radar.bod import DIRECTIVE_URL, FORENSIC_TRIAGE_NOTE, GUIDANCE_URL
from kev_radar.metrics import is_open
from kev_radar.textsafe import md_text


def _esc(value: object) -> str:
    return html.escape("" if value is None else str(value))


def _date_text(value: object) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return "—"
    try:
        if pd.isna(value):
            return "—"
    except TypeError:
        pass
    return str(value)[:10]


def render_html_report(
    findings: pd.DataFrame,
    stats: dict,
    top: pd.DataFrame,
    as_of: date,
    *,
    estate: str = "Harborline Mutual",
    synthetic: bool = True,
) -> str:
    """A single HTML file a CISO can print to PDF from the browser."""
    forecast = stats["forecast"]
    slo = stats["slo"]
    mttr = stats.get("mttr")
    mttr_text = "—" if mttr is None else f"{float(mttr):.0f} days"
    rows = []
    if not top.empty:
        for index, record in enumerate(top.itertuples(index=False), start=1):
            rows.append(
                "<tr>"
                f"<td>{index}</td>"
                f"<td>{_esc(record.cve)}</td>"
                f"<td>{_esc(record.host_name)}</td>"
                f"<td>{_esc(getattr(record, 'owner', ''))}</td>"
                f"<td>{_esc(getattr(record, 'sla_status', ''))}</td>"
                f"<td>{_esc(getattr(record, 'score', ''))}</td>"
                f"<td>{_esc(getattr(record, 'reason', ''))}</td>"
                "</tr>"
            )
    body_rows = "\n".join(rows) or "<tr><td colspan='7'>No open findings in this filter.</td></tr>"
    open_count = stats.get("open", 0)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>KEV Radar executive report — {_esc(estate)} — {_esc(as_of.isoformat())}</title>
<style>
  :root {{ color-scheme: light; }}
  body {{ font-family: "Segoe UI", "Source Sans 3", Helvetica, Arial, sans-serif; color: #1c2430; margin: 2rem auto; max-width: 920px; line-height: 1.45; }}
  h1 {{ font-size: 1.7rem; margin-bottom: 0.2rem; }}
  .kicker {{ letter-spacing: 0.12em; text-transform: uppercase; color: #8a5a10; font-size: 0.75rem; font-weight: 700; }}
  .meta {{ color: #526070; margin-top: 0; }}
  .cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.6rem; margin: 1.2rem 0; }}
  .card {{ border: 1px solid #d5dde6; border-radius: 8px; padding: 0.6rem 0.7rem; }}
  .card span {{ display: block; color: #526070; font-size: 0.78rem; }}
  .card strong {{ font-size: 1.35rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.92rem; }}
  th, td {{ text-align: left; vertical-align: top; border-bottom: 1px solid #e2e8ef; padding: 0.4rem 0.35rem; }}
  th {{ font-size: 0.75rem; letter-spacing: 0.04em; text-transform: uppercase; color: #526070; }}
  .note {{ background: #f7f4ee; border-left: 3px solid #c48a2a; padding: 0.7rem 0.9rem; }}
  footer {{ color: #526070; font-size: 0.82rem; margin-top: 1.5rem; }}
  @media print {{ body {{ margin: 0.6in; }} .cards {{ break-inside: avoid; }} }}
</style>
</head>
<body>
<p class="kicker">Board packet · remediation operations</p>
<h1>KEV Radar — {_esc(estate)}</h1>
<p class="meta">As of {_esc(as_of.isoformat())}. {"Synthetic estate." if synthetic else "Uploaded scanner export."} CVE identifiers and the vulnerability feeds are public. This packet is a status report, not a prediction.</p>
<div class="cards">
  <div class="card"><span>Open findings</span><strong>{int(open_count)}</strong></div>
  <div class="card"><span>Overdue under BOD 26-04</span><strong>{int(stats.get("overdue", forecast.already_overdue))}</strong></div>
  <div class="card"><span>Due in 7 days</span><strong>{int(stats.get("due_soon", forecast.due_in_window))}</strong></div>
  <div class="card"><span>Projected misses</span><strong>{int(forecast.projected_misses)}</strong></div>
  <div class="card"><span>SLO compliance</span><strong>{float(slo["percent"]):.0f}%</strong></div>
  <div class="card"><span>Avg time to fix</span><strong>{_esc(mttr_text)}</strong></div>
  <div class="card"><span>Active exceptions</span><strong>{int(stats.get("active_exceptions", 0))}</strong></div>
  <div class="card"><span>Close rate</span><strong>{float(forecast.weekly_close_rate):.1f}/wk</strong></div>
</div>
<p class="note">{_esc(forecast.statement)}</p>
<h2>Top 10 to fix this week</h2>
<table>
<thead><tr><th>#</th><th>CVE</th><th>Host</th><th>Owner</th><th>SLA</th><th>Score</th><th>Why this week</th></tr></thead>
<tbody>
{body_rows}
</tbody>
</table>
<footer>
<p>Deadlines follow CISA BOD 26-04. Clock start is the earlier of KEV addition and first seen on the asset. Active exceptions are left out of the overdue count and the projection. Fix-on-upgrade findings have no day count.</p>
<p>Sources: <a href="{DIRECTIVE_URL}">BOD 26-04</a> · <a href="{GUIDANCE_URL}">implementation guidance</a>.</p>
<p>{_esc(FORENSIC_TRIAGE_NOTE)}</p>
</footer>
</body>
</html>
"""


def render_tickets(findings: pd.DataFrame, as_of: date, *, limit: int = 15) -> str:
    """One Markdown issue per open finding, suitable for GitHub or Jira."""
    if findings.empty:
        return f"# Remediation tickets\n\nNo open findings on {as_of.isoformat()}.\n"
    open_rows = findings[findings["state"].map(is_open)].copy()
    if "sla_paused" in open_rows.columns:
        paused = open_rows["sla_paused"].map(bool)
        open_rows = open_rows.assign(_paused=paused.astype(int))
        open_rows = open_rows.sort_values(["_paused", "score"], ascending=[True, False])
    else:
        open_rows = open_rows.sort_values("score", ascending=False)
    open_rows = open_rows.head(limit)
    blocks = [
        f"# Remediation tickets — {as_of.isoformat()}",
        "",
        "Paste each section into GitHub or Jira. Figures below are copied from the queue.",
        "",
    ]
    for record in open_rows.itertuples(index=False):
        deadline = _date_text(getattr(record, "deadline", None))
        forensics = "Yes" if bool(getattr(record, "forensics_required", False)) else "No"
        blocks.extend(
            [
                f"## {md_text(record.cve)} on {md_text(record.host_name)}",
                "",
                f"- **Owner:** {md_text(getattr(record, 'owner', '') or 'Unassigned')}",
                f"- **Business unit:** {md_text(getattr(record, 'business_unit', '') or 'Unassigned')}",
                f"- **SLA:** {md_text(getattr(record, 'sla_status', ''))}",
                f"- **Deadline:** {deadline}",
                f"- **Priority score:** {float(getattr(record, 'score', 0) or 0):.1f} ({md_text(getattr(record, 'band', ''))})",
                f"- **Forensic triage required by the BOD path:** {forensics}",
                f"- **Decision path:** {md_text(getattr(record, 'decision_path', ''))}",
                "",
                "### Why",
                "",
                md_text(getattr(record, "score_summary", "") or "See the decision path."),
                "",
                "### Acceptance",
                "",
                "- [ ] Patch, mitigate, or remove the vulnerable software",
                "- [ ] Confirm the asset exposure tag still matches the network",
                "- [ ] If forensic triage is required, collect evidence before the patch and record whether the host was compromised",
                "",
            ]
        )
    return "\n".join(blocks)
