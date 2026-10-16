# HANDOFF — KEV Radar v2

Public demo app. Synthetic data only. No employer exports, hostnames, keys, or secrets.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run streamlit_app.py --server.port 8741
python -m pytest -q          # pytest and ruff are dev dependencies, not in requirements.txt
ruff check .
python scripts/refresh_snapshots.py
```

Python 3.12. Streamlit Community Cloud uses `streamlit_app.py`, `requirements.txt`, and `runtime.txt`.

The app reads `data/snapshots/` first. `cached_bundle` and `cached_parse` are wrapped in `st.cache_data(ttl=86400)`. If `metadata.json` `fetched_at` is 20 hours old or newer, KEV stays on the snapshot and no live catalog request is made. Older snapshots fall through to a cached live pull of the CISA JSON. EPSS scores missing from the snapshot are fetched for at most 100 CVEs, also cached for a day. Failures are not cached, so the next rerun tries again.

A CVE that is not in `vulnrichment.json` is fetched from `https://raw.githubusercontent.com/cisagov/vulnrichment/develop/{year}/{thousands}xxx/{cve}.json`, cached for a day. HTTP 404 is cached as "not published" and the row keeps the No / Total fallback, marked assumed. Any other error is not cached. The live pass stops at 40 CVEs per run. The bundled pool is fully enriched, so the default demo makes no Vulnrichment call.

On this machine, October 16, 2026: snapshot load 0.02 s, CSV parse 0.85 s, prioritize 0.07 s for 1,230 findings. The parse result is cached, so changing pages does not parse the CSV again.

`.github/workflows/refresh-data.yml` runs `python scripts/refresh_snapshots.py --rotate` daily at 07:20 UTC and commits `data/snapshots` and `data/demo` when they change. `.github/workflows/tests.yml` runs ruff (`ruff==0.17.1`, rules E4/E7/E9/F/I, line length ignored) and pytest on push and pull request. The refresh workflow has not been executed from this environment; the files in `data/` were produced by running the script locally on 2026-10-16.

## Structure

```
streamlit_app.py          Streamlit entry. Pages: Overview, Fix queue, Attack surface, What-if, Remediation, KEV this week, Windows patches, Briefing, Signals, About
kev_radar/bod.py          BOD 26-04 table, clock, deadline, decision path, forensic-triage steps
kev_radar/exposure.py     Generally-public-facing step, labeled when it is a stand-in
kev_radar/enrich.py       Live Vulnrichment fetch and the snapshot merge
kev_radar/ssvc.py         Classic CISA SSVC (36 rows), sidebar toggle only
kev_radar/scoring.py      0–100 score and Critical/High/Medium/Low bands
kev_radar/parse.py        Tenable VM export and Nessus-style header aliases
kev_radar/prioritize.py   Join findings to KEV, EPSS, and Vulnrichment
kev_radar/metrics.py      SLA status, aging, MTTR, SLO, burndown, breach forecast
kev_radar/overview.py     KPIs, 8-week trend, overdue projection, top 10 reasons
kev_radar/surface.py      Exposure × KEV × EPSS heatmap and the host drill-down
kev_radar/simulate.py     What-if removal of open findings or a KB
kev_radar/report.py       Print-ready HTML board packet and Markdown tickets
kev_radar/exceptions.py   Risk-acceptance register, CSV/JSON import and export, operator file
kev_radar/msrc.py         CVRF KB extraction and the read-only PowerShell audit
kev_radar/briefing.py     Offline template, live chat call, fact checker
kev_radar/kevdiff.py      7-day catalog window, snapshot diff, Monday Markdown
kev_radar/generate.py     Harborline Mutual lab (seed 2604, 300 hosts)
kev_radar/feeds.py        Snapshot IO and the public HTTP clients
kev_radar/present.py      Frames for the queue, scatter, and vendor chart
scripts/refresh_snapshots.py
data/snapshots/           kev.json, kev_previous.json, epss.json, vulnrichment.json, cve_pool.json, msrc_kb.json, metadata.json
data/demo/tenable_findings.csv
data/operator/            gitignored exceptions.json written by the app
tests/                    deadline, exposure, enrichment, scoring, CSV, metrics, exceptions, MSRC, briefings, diff, generator, overview, surface, what-if, report
```

## Decisions

### BOD 26-04 source of truth

Direct `GET` of the directive HTML from this environment returned **HTTP 403** on 2026-10-16 (the same class of block as the earlier 404). The page is published. Its indexed text includes the clock-start sentence and the forensic-triage definition used below. The implementation guidance page was retrieved in full.

- Directive: <https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk>
- Implementation guidance, issued June 10, 2026 and updated August 25, 2026: <https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk>
- CERT/CC model `cisa:BOD2604:1.0.0`, all 16 rows: <https://certcc.github.io/SSVC/howto/cisa_response/>
- The directive says Automatable and Technical Impact use the Vulnrichment definitions documented with CERT/CC SSVC. The 16 cells in code are that table. Qualys's BOD 26-04 page and Harpia's BOD table reproduce the same cells.
- Live KEV feed in the snapshot: `catalogVersion` 2026.10.16, 1,748 entries. `requiredAction` cites BOD 26-04. `forensicTriage` is `Yes` or `No`.

The clock sentence from the directive: the timelines in Table 1 begin when either (1) CISA adds the vulnerability to the KEV catalog, or (2) pursuant to BOD 23-01, the agency enumerates or identifies it on an asset and updates the CDM dashboard. Whichever event occurs first starts the remediation timeline. `resolve_clock` implements that. First seen stands in for the enumeration. The path text says which date won and cites the rule.

- In KEV: `min(dateAdded, first_observed)`.
- Not in KEV: `first_observed` only.

That is why an old KEV such as CVE-2023-27350 can show a 2023 deadline on a host first scanned this year. Deadline = clock start + N days. The due date itself is still on time (`days_left` 0). Overdue starts the next day. A catalog `dueDate` is shown beside the asset deadline and is not asset-specific. Fix-on-upgrade rows have no deadline and are excluded from SLO and from the breach forecast. The directive defines fix on system upgrade as the next scheduled major upgrade or rebuild, unless the decision points change.

The 16 outcomes, as `(in KEV, exposed, automatable, technical impact)`:

| Path | Outcome |
|---|---|
| F,F,F,partial and F,F,F,total | Fix on system upgrade (no day count) |
| F,T,F,partial and F,F,T,partial and F,F,T,total | 60 days |
| T,F,F,partial and T,T,F,partial and T,F,T,partial and F,T,T,partial and T,F,F,total and F,T,F,total | 14 days |
| T,T,T,partial and F,T,T,total | 3 days |
| T,T,F,total and T,F,T,total and T,T,T,total | 3 days + forensic triage |

### Forensic triage

Directive text: "& forensic triage" means remediate or mitigate within three days and carry out a forensic triage to assess whether the system is compromised. An adequate triage follows the implementation guidance. The six steps in `FORENSIC_TRIAGE_STEPS` are that guidance: scoping, preserve and collect evidence, critical patching and stabilization, contain and control, triage analysis, escalation decision. The hour ranges (2 hours through 72 hours) are recommended best practice. The directive does not require that specific timeline. A KEV entry's own notes override the baseline when CISA publishes them. The fix-queue detail and the About page both say this.

### Missing SSVC

Implementation-guidance FAQ: if Automatable is unpublished, treat it as No; if Technical Impact is unpublished, treat it as Total. The guidance states this for non-KEV CVEs. The app uses the same stand-in when a KEV CVE has no Vulnrichment row, and the decision path is marked `(assumed)`. The bundled pool is fully enriched, so the default demo shows zero assumed rows. An upload outside the snapshot is fetched live first. Only a 404, a failed call, or a record that still lacks the field falls through to the assumption.

### Exposure

Order, from the same FAQ:

1. An explicit Internet Exposed tag or column wins, including `No` on a public IP and `Yes` on a private IP.
2. Else a publicly routable address (`ipaddress.IPv4Address.is_global`). RFC1918 and the documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) are not public. The lab uses 10.x and 203.0.113.x, so exposure comes from the tag, not the address.
3. Else asset type exactly `network` is treated as public.
4. Else, for a KEV-listed CVE, generally public-facing software is treated as public.
5. Else internal.

Step 4 is implemented. CISA has not published the product list behind "CISA's analysis." Two inputs are accepted:

- An operator column or tag (`generally public-facing`, `public facing software`) is an attestation. It is not marked assumed. It applies only when the CVE is in KEV, matching the FAQ.
- Otherwise `match_public_facing` looks for edge and remote-access names (VPN, firewall, PAN-OS, FortiGate, Cisco ASA, and the rest of the list in `exposure.py`). A hit is marked `(assumed)` on the decision path and the reason says CISA has not published the list. An Internet Exposed tag overrides it.

The bundled estate sets Internet Exposed on every host, so the demo shows zero assumed-exposure rows. The step shows up on an upload that omits the tag.

### Score

`35 + 10 + 25 + 20 + 10`. EPSS is clamped to 0–1 (a scanner value above 1 is treated as a percent). CVSS is clamped to 0–10. Missing EPSS or CVSS contributes 0 and the breakdown says so. Bands: Critical ≥ 70, High ≥ 40, Medium ≥ 15, else Low. Scanner CVSS wins over the Vulnrichment CVSS. Scanner EPSS is used only when FIRST has no score. Portfolio risk on the overview and the what-if page is the sum of open finding scores, including paused rows. The vulnerability is still present.

### Classic SSVC toggle

The 36-row CISA coordinator table (Exploitation, Automatable, Technical Impact, Mission & well-being → Track / Track* / Attend / Act) is checked against the CISA SSVC guide. Vulnrichment does not carry mission prevalence. The sidebar default is **medium**, chosen in the UI, not a silent CISA default. If Exploitation is missing: in KEV → `active` (assumed), else `none` (assumed). Turning the toggle on does not change the BOD deadline.

### Remediation math

- **Time to fix** is `last_fixed - first_observed`, grouped by severity, owner, and business unit. It is not the BOD clock.
- **SLO** counts findings that have a day-count deadline. A finding is compliant when it was fixed on or before the deadline, or it is still open and today is on or before the deadline. Fix-on-upgrade is excluded. The bundled lab sits near 20% because hundreds of open historical KEVs are already past the catalog clock.
- **Aging** uses age since first seen: 0–7, 8–14, 15–30, 30+.
- **Forecast** looks at open findings whose deadline falls in `[as_of, as_of + 7 days]`. Expected closes = fixes in the prior 28 days / 4. Projected misses = max(0, due in window − expected closes). Already-overdue findings are excluded from the projection and printed separately. The sentence in the UI is labeled as a projection.
- **Trend** (`risk_trend`) replays which findings were open at each of the last 8 week endings. Earlier weeks do not replay exceptions. The latest overdue point subtracts today's active pauses on rows whose raw SLA status is Overdue, so it matches the KPI.
- **Burn-down** (`projected_burndown`) holds today's overdue stock and subtracts the recent weekly close rate for four weeks. New findings that will become overdue are not in that line. The chart caption says so.
- **Top 10** is open findings that are not paused: Overdue, then Due soon, then score. The one-line reason is built only from fields on the row.
- The generator keeps this week's KEVs open, fixes most older KEVs, and places those fixes at least 29 days ago so they do not inflate the 4-week close rate.

### What-if

`simulate` drops the selected open host+CVE keys and reruns `breach_forecast` and `portfolio_risk`. Dropped rows are not written back as fixes inside the last 28 days, so the close rate does not jump. A KB is resolved with `normalize_kb` against `msrc_kb.json`. Every open instance of a matched CVE is included. The UI offers the first 40 open rows in the current sort, plus a CVE box and a KB box.

### Exports

`render_html_report` is one self-contained HTML file with print CSS. It is the board packet. Print to PDF from the browser. There is no PDF library in `requirements.txt`. `render_tickets` writes one Markdown issue per open finding (15 by default), GitHub or Jira shaped, using only queue fields. CSV reuses `csv_download`.

### KEV this week

The window is `as_of` and the six days before it (inclusive). `as_of` is `date.today()` in the app. A second list, `snapshot_only`, holds CVE IDs present in `kev.json` and absent from `kev_previous.json` that fall outside that window.

The initial `kev_previous.json` is the catalog with entries added on or after 2026-10-10 removed, so the first diff matches the 7-day window. Later runs of the workflow pass `--rotate`, which copies the current `kev.json` onto `kev_previous.json` before the download. Do not rotate by hand if you still want the first-week story.

`forensicTriage` missing or blank → status `not_in_feed`, label "Not in this feed". Any other unrecognized value → `unrecognized`. Ransomware is `knownRansomwareCampaignUse` equal to `Known`, case-insensitive. Estate hits are open or reopened findings only. The Monday note is Markdown from `render_monday_report`. There is no GitHub Issue and no RSS feed.

### Synthetic estate

Fictional owners and business units (Payments, Member Portal, Claims, Identity, Corporate IT, Edge Network). Plugin IDs sit in the 9,000,000 range so they cannot be confused with real Tenable plugin IDs. Output text says the row is synthetic. About 12% of rows are duplicate port lines (443 and 8443) so host+CVE collapse is visible: any open row keeps the finding open, first-seen is the earliest, last-seen is the latest, CVSS is the max, ports are joined. Rows with no CVE or no host are skipped and counted.

Tenable Vulnerability Management export keys are the primary headers. Nessus aliases are accepted. A cell with several CVEs is exploded on `CVE-\d{4}-\d{4,}`. Tags may be a JSON object or `Key:Value` pairs split on `|` or `;`. Owner, Business Unit, Internet Exposed, and Generally Public-Facing columns override tags.

### Demo pool

`scripts/refresh_snapshots.py` keeps every KEV added in the last 45 days, 18 older ransomware KEVs, 12 other older KEVs, and 30 non-KEV CVEs. Non-KEV IDs come from NVD 2.0 windows (no API key; the script sleeps 6 seconds between calls) and are enriched from `https://cveawg.mitre.org/api/cve/{cve}`. The 30 are round-robin across the four (Automatable × Technical Impact) shapes. EPSS is requested in chunks of 100. CVSS prefers the CNA metric over an ADP metric. SSVC options are read from `containers.adp[].metrics[].other` where `type` is `ssvc`.

The October 16, 2026 bundle: KEV 1,748; EPSS 1,778 scores dated 2026-10-16; Vulnrichment 121 (the pool); MSRC 16 CVEs and 129 KB articles. CVE-2014-4113 and CVE-2014-4148 are in that set with an empty patch list because the API returned no security update. User-Agent on outbound calls is `kev-radar-portfolio/1.0`.

`python scripts/refresh_snapshots.py --msrc-only` rebuilds `msrc_kb.json` from the Microsoft and Windows CVEs in `cve_pool.json` without re-downloading KEV. A failure there is logged and the previous KB file is left in place.

### Exceptions

An exception records `exception_id`, host, CVE, owner, justification, compensating controls, expiry, and approver. Blank required fields raise `ValueError`. The expiry date is still active. The next day the status is Expired.

`apply_exceptions` sets `sla_paused` on an open finding with an active exception and changes `sla_status` to `Exception`. The previous label stays on `sla_status_raw`. Breach forecast skips paused rows for both the overdue count and the 7-day window, and the statement says they were left out. SLO skips them too. Aging and time-to-fix are unchanged. An expired exception does not pause anything.

If two records cover the same host and CVE, the active one wins. Two active records keep the later expiry.

The bundled demo seeds eight exceptions from the highest-scoring overdue findings (five active, three expired) with fictional approvers Morgan Ellis, Rita Okonkwo, and Helen Cho. Uploads start with an empty seed. Rows added, imported, or removed are stored in `st.session_state` and written to `data/operator/exceptions.json`. That directory is gitignored. The seed is rebuilt when the estate token changes. The operator file is reloaded, so an imported register survives a reload of the process only if the file is still on disk. Download offers the canonical CSV and JSON (`exception_id`, `host_name`, `cve`, `owner`, `justification`, `compensating_controls`, `expiry`, `approver`). Import also accepts the on-screen headers (`ID`, `Host`, `CVE`, …). Invalid rows are reported and skipped.

On the October 16, 2026 estate that seed pauses 5 findings, so overdue is 337, due-in-7-days stays 43, and the projection stays about 20 misses at 23.5 closes a week.

### Windows KB mapper

`GET https://api.msrc.microsoft.com/cvrf/v3.0/Updates/{cve}` returns the monthly security-update id. `GET https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{id}` is the CVRF document. Vendor-fix remediations are `Type` 2. The KB is `Description.Value` (digits, normalized to `KBnnnnnn`). Type 3 knowledge-base links are not treated as extra patches. Product names come from `ProductTree.FullProductName`. Each KB keeps up to eight products and eight fixed builds.

The app renders from `data/snapshots/msrc_kb.json`. The Windows page offers a live lookup only for CVEs in the filter that are missing from that file, cached with `st.cache_data(ttl=86400)`. A network error is not cached. The row then stays on the snapshot. A 404 is stored as an empty patch list.

`render_audit_script` emits a comment header, a CSV here-string parsed with `ConvertFrom-Csv`, then `Get-CimInstance -ClassName Win32_QuickFixEngineering` and `Get-HotFix`. Both are reads. Output is `Installed` or `Not installed` for the computer where the script is run. Host names from the export are comments, not remoting targets. The function refuses to return a script that still contains a cmdlet in `REMEDIATION_CMDLETS`. The app never executes the script.

### Briefings

`build_facts` copies counts, the top eight open findings, and up to five exceptions into one JSON object. `render_offline` writes the executive note and one ticket per owner using only those fields. That is the default.

`check_text` extracts CVE IDs, dotted hostnames, IPv4 addresses, and numbers from the output. Each must appear somewhere in the facts JSON. This is a presence test, not a claim binder. The offline template is tested to pass its own checker. A live draft that fails is shown as rejected and is not offered as the briefing.

Live mode posts to `{base}/chat/completions` with `Authorization: Bearer`. The key is not in the body. The key is only the one typed into the password field. There is no fallback to `KEV_RADAR_LLM_API_KEY`, `OPENAI_API_KEY`, or a Streamlit secret: on a public deployment that fallback let any anonymous visitor spend the owner's key, and because the base URL was also an editable field on the page, a visitor could send that key in the Authorization header to a server of their choosing. The endpoint now comes from configuration only (`KEV_RADAR_LLM_BASE_URL`, then a Streamlit secret, then the default `https://api.openai.com/v1`), is shown read-only on the page, and `complete_live` refuses anything that is not https before sending. `KEV_RADAR_LLM_MODEL` (default `gpt-4o-mini`) still sets the default model, which the visitor may change. No key is written to disk. Missing `secrets.toml` is ignored. `tests/test_briefing.py` pins each of these, and those tests fail against the previous code.

### Theme

`.streamlit/config.toml` is the dark theme (background `#0b1117`, brass `#e0a33a`). The app CSS loads Source Sans 3 and IBM Plex Mono with a system-font fallback, styles the metric cards, and keeps the decision path in a mono block. Plotly charts use a transparent background and the same brass and steel colors. Metric widgets carry a `help` tooltip. Empty filters and a missing snapshot have their own messages. A page can be opened with `?page=Overview` (and the other page names) so a screenshot run does not depend on clicking the sidebar.

## What works

- Default load of the bundled CSV, CSV upload, and seed regeneration. No login.
- All 16 BOD paths, with the decision path and the directive's clock sentence on the row.
- The exposure order, including a labeled generally-public-facing stand-in.
- Forensic triage steps, with the hour ranges labeled as recommended.
- Score, bands, and the classic SSVC toggle.
- Executive overview: KPIs, risk trend, overdue burn-down, top 10 with reasons.
- Attack-surface heatmap and a per-host decision path.
- What-if for findings, CVEs, and a KB, without inflating the close rate.
- HTML board packet, Markdown tickets, and CSV.
- SLA labels, aging, average time to fix, SLO, burndown, and the 7-day breach forecast.
- Exceptions register with import and export, and a gitignored operator file that survives a reload.
- Live Vulnrichment for CVEs outside the snapshot, with the cached fallback.
- KEV-this-week table, ransomware and forensic-triage flags, and a Markdown download.
- MSRC KB table and a read-only PowerShell audit.
- Offline executive briefing and ticket drafts. The fact checker rejects unknown CVEs, hostnames, and numbers.
- `python -m pytest -q` — 97 tests on 2026-10-16 (92 before the live-key fix below).

## Known issues

- This environment could not download the directive HTML (HTTP 403). The clock sentence and the forensic-triage definition are from the published page's indexed text, and the 16 cells are the CERT/CC table the directive points at. If CISA edits Table 1, re-read the page and adjust `DECISION_TABLE`.
- The generally-public-facing product list is KEV Radar's labeled stand-in. It is not CISA's unpublished analysis. Rows it flips are marked assumed.
- SLO on the bundled lab is low on purpose: open historical KEVs are already past a clock that started at `dateAdded`.
- This week's new KEVs all appear in the estate because the generator places each of them. That is a demo choice, not a property of a real upload.
- The week of October 10–16, 2026 had forensic-triage hits and no new `knownRansomwareCampaignUse=Known` entries. Older open ransomware findings still show in the caption and in the score.
- Live EPSS backfill stops at 100 CVEs per session. Live Vulnrichment stops at 40.
- NVD is only used while building the pool. A flaky NVD window falls back to EPSS-list offsets in the refresh script.
- The top of the queue is often an old, exposed KEV. On the bundled estate some of those rows are under a seeded exception, so the SLA label says Exception while the decision path still shows the underlying deadline. The top-10 list leaves paused rows off.
- The fact checker allows any number that appears anywhere in the facts, including digits inside a CVE id or a date. It does not prove the sentence used that number for the right claim.
- The KB snapshot covers Microsoft and Windows CVEs in the demo pool, not every CVE an upload might contain. CVEs MSRC does not publish stay as an empty patch list.
- The PowerShell script checks the machine it runs on. It does not connect to the fictional hosts named in the comments.
- Live briefings are untested against a real model in this environment. No key was available, and none is stored.
- The operator exceptions file is local to the machine running Streamlit. Community Cloud will not keep it across a new container. The CSV and JSON download are the portable copy.
- The overdue projection does not model findings that will become newly overdue. The chart says so.

## Next

- Publish the Monday note as a GitHub Issue or an RSS item. The Markdown download is the stand-in.
- If CISA publishes the generally-public-facing product list, replace `match_public_facing` with that list and drop the assumed flag for those rows.
- Bind the fact checker to the field a number came from, not merely to presence in the facts JSON.

## History

- **2026-10-16 — Live briefing key fallback removed (security fix).** Found in a read-through before the first deployment: the Briefing page fell back to a server-side key when the visitor left the field blank, while the API base URL was editable on the page. Deployed as the README instructed (key in Streamlit secrets), any visitor could have spent that key or sent it to their own server. Fixed as described under Briefings: visitor key only, endpoint from configuration only, https enforced before sending. Not exploitable before the fix in practice, because no key had been configured and the app had not been deployed. Verified: `ruff check .` clean; `python -m pytest -q` 97 passed on Python 3.12.12; the 5 new tests fail against the previous code. Commits in this repo now use the GitHub no-reply address, set in this clone's local git config.
