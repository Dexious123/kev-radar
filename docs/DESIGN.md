# KEV Radar: design notes

Synthetic data only. No employer exports, hostnames, keys, or secrets.

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

Measured on a laptop on October 16, 2026: snapshot load 0.02 s, CSV parse 0.85 s, prioritize 0.07 s for 1,230 findings. The parse result is cached, so changing pages does not parse the CSV again.

`.github/workflows/refresh-data.yml` runs `python scripts/refresh_snapshots.py --rotate` daily at 07:20 UTC and commits `data/snapshots` and `data/demo` when they change. Each run also moves the lab forward one simulated day (see Living estate). `.github/workflows/tests.yml` runs ruff (`ruff==0.17.1`, rules E4/E7/E9/F/I, line length ignored) and pytest on push and pull request. The first scheduled refresh ran successfully on 2026-10-17.

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
kev_radar/evolve.py       Moves the lab forward one simulated day at a time
kev_radar/radar.py        The deadline radar SVG; radar.js is its data block
kev_radar/feeds.py        Snapshot IO and the public HTTP clients
kev_radar/present.py      Frames for the queue, scatter, and vendor chart
scripts/refresh_snapshots.py
data/snapshots/           kev.json, kev_previous.json, epss.json, vulnrichment.json, cve_pool.json, msrc_kb.json, metadata.json
data/demo/tenable_findings.csv, estate_log.json
data/operator/            gitignored exceptions.json, written only when KEV_RADAR_OPERATOR_FILE=1
tests/                    deadline, exposure, enrichment, scoring, CSV, metrics, exceptions, MSRC, briefings, diff, generator, overview, surface, what-if, report
```

## Decisions

### BOD 26-04 source of truth

A scripted `GET` of the directive page returned **HTTP 403** on 2026-10-16. The page is published. Its indexed text includes the clock-start sentence and the forensic-triage definition used below. The implementation guidance page was retrieved in full.

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

Implementation-guidance FAQ: if Automatable is unpublished, treat it as No; if Technical Impact is unpublished, treat it as Total. The guidance states this for non-KEV CVEs. The app uses the same stand-in when a KEV CVE has no Vulnrichment row, and the decision path is marked `(assumed)`. Nearly every CVE in the bundled pool has published SSVC values. The few that do not (for example a fresh KEV that Vulnrichment has not scored yet) show as assumed rows, and the header counts them. An upload outside the snapshot is fetched live first. Only a 404, a failed call, or a record that still lacks the field falls through to the assumption.

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

The daily workflow passes `--rotate`, which copies the current `kev.json` onto `kev_previous.json` before the download, so `snapshot_only` is whatever CISA added since the previous run. When the catalog did not change between runs, the two files are identical and the list is empty. The 7-day window does not depend on the rotation; it reads `dateAdded`.

`forensicTriage` missing or blank → status `not_in_feed`, label "Not in this feed". Any other unrecognized value → `unrecognized`. Ransomware is `knownRansomwareCampaignUse` equal to `Known`, case-insensitive. Estate hits are open or reopened findings only. The Monday note is Markdown from `render_monday_report`. There is no GitHub Issue and no RSS feed.

### Synthetic estate

Fictional owners and business units (Payments, Member Portal, Claims, Identity, Corporate IT, Edge Network). Plugin IDs sit in the 9,000,000 range so they cannot be confused with real Tenable plugin IDs. Output text says the row is synthetic. About 12% of rows are duplicate port lines (443 and 8443) so host+CVE collapse is visible: any open row keeps the finding open, first-seen is the earliest, last-seen is the latest, CVSS is the max, ports are joined. Rows with no CVE or no host are skipped and counted.

Tenable Vulnerability Management export keys are the primary headers. Nessus aliases are accepted. A cell with several CVEs is exploded on `CVE-\d{4}-\d{4,}`. Tags may be a JSON object or `Key:Value` pairs split on `|` or `;`. Owner, Business Unit, Internet Exposed, and Generally Public-Facing columns override tags.

### Living estate

The bundled CSV used to be regenerated from scratch every morning, so nothing that happened the day before was remembered and the trend charts were re-invented daily. `kev_radar/evolve.py` now moves the lab forward one simulated day per calendar day, and the refresh job calls it instead of the generator. Each day, in order:

1. The scanner rescans: every open or reopened row gets `last_seen` set to that day.
2. KEV entries from the pool whose `dateAdded` falls in the last three days, and whose CVE the estate does not hold yet, land on hosts whose family matches: one exposed and one internal host when both exist, plus up to two more.
3. The scanner finds 0–3 non-KEV CVEs from the pool on matching hosts that never had them.
4. Owners close findings: three to six on a weekday (one more while more than 600 host-and-CVE findings are open), none or one at the weekend. Picks are weighted: critical ×2, high ×1.5, exposed ×2, KEV ×3, and a KEV first seen in the last 14 days ×10 more. A finding is never closed the day it appears, and closing it closes all its port rows.
5. With probability 0.12, one finding fixed in the last 60 days reopens.
6. Fixed rows older than 180 days leave the export.

Hosts, owners, and exposure are rebuilt from the export itself (asset columns, the `asset.tags` JSON, and the role in the asset name), so the lab needs no side file. New rows take plugin IDs above the current maximum. The random generator for a day is seeded with `"{seed}:{date}"`, so replaying a day from the same input gives the same output. `data/demo/estate_log.json` records the lab's date and the last 30 days of events; a run on a day the lab has already reached changes nothing, missed days are replayed one at a time (at most the last 31), and a missing or unreadable log means the lab is generated fresh. `--rebuild` does that on purpose; `--estate-only` advances from the pool on disk with no downloads.

The pool is re-picked every morning, while the lab keeps its findings. Before enrichment, the refresh job therefore carries every CVE the estate still holds into the pool: from the KEV catalog when it is listed there, from yesterday's `cve_pool.json` otherwise, and from the CSV row as a last resort. That keeps CVSS, EPSS, Vulnrichment, and MSRC coverage for older findings.

The pace was tuned by simulation, not by feel. Starting from the generated October 17 lab and injecting about five new KEV entries a week, weekly readings over 180 simulated days kept open findings between 578 and 606, overdue between 355 and 426, the export between about 1,260 and 1,620 rows, and the weekly close rate between about 20 and 31. Of 344 new KEV host-and-CVE findings, half were fixed within 9 days, and about a third ran past 14 days (fixed late or still open), which is the kind of slippage the dashboard exists to show.

Day zero was generated as of October 16, 2026 and advanced one day by the same code the job runs, so the first visitors already see a day of history. October 17 was a Saturday: one finding closed and one new non-KEV finding appeared (on the fix-on-upgrade path, so it has no deadline and no radar dot).

The header line comes from the log's latest day: "Across the lab since yesterday: …" when that day is today, otherwise the date. Findings whose `first_observed` is the latest scan day wear an open ring on the radar, and stay plotted even above the 700-dot cap.

### Demo pool

`scripts/refresh_snapshots.py` keeps every KEV added in the last 45 days, 18 older ransomware KEVs, 12 other older KEVs, and 30 non-KEV CVEs. Non-KEV IDs come from NVD 2.0 windows (no API key; the script sleeps 6 seconds between calls) and are enriched from `https://cveawg.mitre.org/api/cve/{cve}`. The 30 are round-robin across the four (Automatable × Technical Impact) shapes. EPSS is requested in chunks of 100. CVSS prefers the CNA metric over an ADP metric. SSVC options are read from `containers.adp[].metrics[].other` where `type` is `ssvc`.

The October 16, 2026 bundle: KEV 1,748; EPSS 1,778 scores dated 2026-10-16; Vulnrichment 121 (the pool); MSRC 16 CVEs and 129 KB articles. CVE-2014-4113 and CVE-2014-4148 are in that set with an empty patch list because the API returned no security update. User-Agent on outbound calls is `kev-radar/1.0 (+https://github.com/Dexious123/kev-radar)`.

`python scripts/refresh_snapshots.py --msrc-only` rebuilds `msrc_kb.json` from the Microsoft and Windows CVEs in `cve_pool.json` without re-downloading KEV. A failure there is logged and the previous KB file is left in place.

### Exceptions

An exception records `exception_id`, host, CVE, owner, justification, compensating controls, expiry, and approver. Blank required fields raise `ValueError`. The expiry date is still active. The next day the status is Expired.

`apply_exceptions` sets `sla_paused` on an open finding with an active exception and changes `sla_status` to `Exception`. The previous label stays on `sla_status_raw`. Breach forecast skips paused rows for both the overdue count and the 7-day window, and the statement says they were left out. SLO skips them too. Aging and time-to-fix are unchanged. An expired exception does not pause anything.

If two records cover the same host and CVE, the active one wins. Two active records keep the later expiry.

The bundled demo seeds eight exceptions from the highest-scoring overdue findings (five active, three expired) with fictional approvers Morgan Ellis, Rita Okonkwo, and Helen Cho. Uploads start with an empty seed. Rows added, imported, or removed are stored in that visitor's `st.session_state` only. A shared file would let one anonymous visitor change the exceptions, and the dashboard numbers, that every other visitor of a public deployment sees, so writing `data/operator/exceptions.json` (gitignored) is opt-in: set `KEV_RADAR_OPERATOR_FILE=1` on a single-user install and the register is saved there and reloaded across restarts. An import over 500 rows is refused rather than partly loaded. Justification and compensating-control text is rendered as plain text, never as Markdown. The seed is rebuilt when the estate token changes. Download offers the canonical CSV and JSON (`exception_id`, `host_name`, `cve`, `owner`, `justification`, `compensating_controls`, `expiry`, `approver`). Import also accepts the on-screen headers (`ID`, `Host`, `CVE`, …). Invalid rows are reported and skipped.

On the October 17, 2026 estate (the screenshots) that seed paused 5 findings, so overdue is 354, due-in-7-days is 27, and the projection is about 4 misses at 23.5 closes a week. The seed follows the lab: when the estate changes, the eight highest-scoring overdue findings are picked again.

### Windows KB mapper

`GET https://api.msrc.microsoft.com/cvrf/v3.0/Updates/{cve}` returns the monthly security-update id. `GET https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{id}` is the CVRF document. Vendor-fix remediations are `Type` 2. The KB is `Description.Value` (digits, normalized to `KBnnnnnn`). Type 3 knowledge-base links are not treated as extra patches. Product names come from `ProductTree.FullProductName`. Each KB keeps up to eight products and eight fixed builds.

The app renders from `data/snapshots/msrc_kb.json`. The Windows page offers a live lookup only for CVEs in the filter that are missing from that file, cached with `st.cache_data(ttl=86400)`. A network error is not cached. The row then stays on the snapshot. A 404 is stored as an empty patch list.

`render_audit_script` emits a comment header, a CSV here-string parsed with `ConvertFrom-Csv`, then `Get-CimInstance -ClassName Win32_QuickFixEngineering` and `Get-HotFix`. Both are reads. Output is `Installed` or `Not installed` for the computer where the script is run. Host names from the export are comments, not remoting targets. The function refuses to return a script that still contains a cmdlet in `REMEDIATION_CMDLETS`. The app never executes the script.

### Briefings

`build_facts` copies counts, the top eight open findings, and up to five exceptions into one JSON object. `render_offline` writes the executive note and one ticket per owner using only those fields. That is the default.

`check_text` extracts CVE IDs, dotted hostnames, IPv4 addresses, and numbers from the output. Each must appear somewhere in the facts JSON. This is a presence test, not a claim binder. The offline template is tested to pass its own checker. A live draft that fails is shown as rejected and is not offered as the briefing.

Live mode posts to `{base}/chat/completions` with `Authorization: Bearer`. The key is not in the body. The key is only the one typed into the password field. There is no fallback to `KEV_RADAR_LLM_API_KEY`, `OPENAI_API_KEY`, or a Streamlit secret: on a public deployment that fallback let any anonymous visitor spend the owner's key, and because the base URL was also an editable field on the page, a visitor could send that key in the Authorization header to a server of their choosing. The endpoint now comes from configuration only (`KEV_RADAR_LLM_BASE_URL`, then a Streamlit secret, then the default `https://api.openai.com/v1`), is shown read-only on the page, and `complete_live` refuses anything that is not https before sending. `KEV_RADAR_LLM_MODEL` (default `gpt-4o-mini`) still sets the default model, which the visitor may change. No key is written to disk. Missing `secrets.toml` is ignored. `tests/test_briefing.py` pins each of these, and those tests fail against the previous code.

### Theme

The design idea is approach control: an air traffic controller sequences arrivals by time to landing, and this console sequences fixes by time to deadline. Everything follows from that. **Hero.** The title, one live sentence about the filtered estate, one sentence on what changed across the lab since yesterday, where the data comes from, and the deadline radar (`kev_radar/radar.py`): every open, unpaused finding with a deadline is a dot, its distance from the center set by days left (past due inside, then 7 days, 30 days, later; the past-due band uses a log scale so a multi-year backlog does not flatten this week's), its slice set by business unit (more than eight fold into Other), and its position inside the slice set by a stable hash of host and CVE, so only slice and distance carry meaning. Each dot's animation delay is computed from its angle, so it brightens as the sweep passes, and the SVG carries a text summary for screen readers. Above 700 findings it keeps the highest scores (and every new contact) and still counts everything. Findings first seen in the latest scan wear an open ring in the signal color, a shape cue rather than a fourth hue. **Data block.** Native SVG tooltips appeared after a delay, looked like the operating system rather than the console, needed the pointer on a dot two to six pixels wide, and did nothing on a phone. `kev_radar/radar.js` replaces them with what a controller reads next to a target: the dot nearest the pointer within 16 px (26 px for a tap) gets a reticle and a leader line to a small block with the CVE and host in the fixed-width face, the owner and business unit, time left beside a band-colored mark, and the deadline date. The block sits beside the dot, or straight above or below it when neither side fits, as on a phone. A click or tap pins it (text can be selected); Escape, a click elsewhere, or a second click closes it. With the radar focused, arrow keys step through findings from the most overdue, and the block is an `aria-live` status so each step is read out. The script is a fixed file loaded through `st.html(..., unsafe_allow_javascript=True)`; it contains no data, reads the dots' HTML-escaped `data-*` attributes, and writes them with `textContent` only. Streamlit runs that HTML through DOMPurify, which drops a script whose text has a less-than sign right before a letter or slash, so a test keeps that pair out of the file. The overlay lives on `document.body`, outside React's tree, and closes itself when a rerun replaces the SVG. **Enlarged view.** A double-click on the radar, Enter while it has focus, or the Enlarge radar button opens a full-screen copy of it (also on `document.body`), sized to the viewport: on a 1440 × 900 screen it grows from 540 to about 1,210 px wide. Data blocks, taps, and arrow keys work inside it; Escape closes the block first and then the view, as do Close, a click on the empty backdrop, or another double-click, and focus returns to the inline radar. On an upright phone the side labels would take half the width, so the copy crops its viewBox to the scope and folds each business-unit label inside the rim, anchored inward; the scope then fills the width, about 1.8 times its inline size. On a short screen (a phone on its side) the title, key, and hint step aside and Close moves to a corner, so the scope gets the full height. The copy renames its `id`s, and the sweep's rotation origin is pinned in user units, because a percentage origin with `transform-box: view-box` follows the viewBox's coordinate origin and would swing the sweep off center once the viewBox is cropped. Phones get a button because double-tap is not a dependable gesture there. **Readouts.** One instrument band divided by hairlines instead of a grid of cards; a figure turns red, with an alert icon, only when it needs attention. **Flight strips.** The ten findings to fix this week (`kev_radar/strips.py`), one strip each, the edge colored by deadline band, identifiers in a fixed-width face as on a printed strip, and the reason without repeating the lateness already shown. **Palette.** Scope `#07161B`, bezel `#0E2229`, graticule `#1E3A42`, signal `#E4F0F1`, readout `#8AA5AB`; one accent, scope cyan `#63D3E3`; amber `#F2B33D` for due within 7 days and red `#FF5B4E` for past due. The three signal colors pass the dataviz validator's colorblind-separation and contrast checks on both surfaces; text contrast is 6:1 or better. Charts use cyan for a single series, a filled-versus-open marker for the KEV split instead of a second hue, red only for the overdue status, and a bezel-to-teal heatmap dark enough for white labels. **Type.** Instrument Sans, set condensed for the title and section headings; Martian Mono only for CVE IDs, hosts, and the decision path. Both load from Google Fonts, with the system font stack as fallback. **Restraint.** No eyebrow labels, no all-caps, sentence-case sidebar headings, one moving element (the sweep), and motion stops for visitors who prefer reduced motion. On phones the sidebar starts collapsed, the hero stacks, and the readouts sit two to a row. The title is a `role="heading"` paragraph because Streamlit wraps a raw `<h1>` in its own anchored heading. Metric widgets keep their `help` tooltips. A page can be opened with `?page=Overview` (and the other page names) so a screenshot run does not depend on clicking the sidebar.

## What works

- Default load of the bundled CSV, CSV upload, and seed regeneration. No login.
- The bundled lab moves forward one simulated day each morning, with a header line for the latest day and rings for new findings on the radar.
- Radar data block on hover, tap, and arrow keys, and an enlarged radar view (double-click, Enter, or the button).
- All 16 BOD paths, with the decision path and the directive's clock sentence on the row.
- The exposure order, including a labeled generally-public-facing stand-in.
- Forensic triage steps, with the hour ranges labeled as recommended.
- Score, bands, and the classic SSVC toggle.
- Executive overview: KPIs, risk trend, overdue burn-down, top 10 with reasons.
- Attack-surface heatmap and a per-host decision path.
- What-if for findings, CVEs, and a KB, without inflating the close rate.
- HTML board packet, Markdown tickets, and CSV.
- SLA labels, aging, average time to fix, SLO, burndown, and the 7-day breach forecast.
- Exceptions register with import and export, private to each visitor's session, with an opt-in operator file for single-user installs.
- Live Vulnrichment for CVEs outside the snapshot, with the cached fallback.
- KEV-this-week table, ransomware and forensic-triage flags, and a Markdown download.
- MSRC KB table and a read-only PowerShell audit.
- Offline executive briefing and ticket drafts. The fact checker rejects unknown CVEs, hostnames, and numbers.
- `python -m pytest -q` — 97 tests on 2026-10-16 (92 before the live-key fix below); see History for later counts.

## Known issues

- The directive page blocks scripted downloads (HTTP 403). The clock sentence and the forensic-triage definition are from the published page's indexed text, and the 16 cells are the CERT/CC table the directive points at. If CISA edits Table 1, re-read the page and adjust `DECISION_TABLE`.
- The generally-public-facing product list is KEV Radar's labeled stand-in. It is not CISA's unpublished analysis. Rows it flips are marked assumed.
- SLO on the bundled lab is low on purpose: open historical KEVs are already past a clock that started at `dateAdded`.
- Every new KEV entry appears in the lab because the generator, and then the daily simulation, place each one on matching hosts. That is a demo choice, not a property of a real upload.
- The simulated close pace, discovery rate, and regressions are chosen to look like a stretched team, not measured from one. Only the CVEs, KEV dates, and scores are real.
- If the refresh job misses more than 31 days, the lab replays only the last 31; the days before that pass with no activity.
- The week of October 10–16, 2026 had forensic-triage hits and no new `knownRansomwareCampaignUse=Known` entries. Older open ransomware findings still show in the caption and in the score.
- Live EPSS backfill stops at 100 CVEs per session. Live Vulnrichment stops at 40.
- NVD is only used while building the pool. A flaky NVD window falls back to EPSS-list offsets in the refresh script.
- The top of the queue is often an old, exposed KEV. On the bundled estate some of those rows are under a seeded exception, so the SLA label says Exception while the decision path still shows the underlying deadline. The top-10 list leaves paused rows off.
- The fact checker allows any number that appears anywhere in the facts, including digits inside a CVE id or a date. It does not prove the sentence used that number for the right claim.
- The KB snapshot covers Microsoft and Windows CVEs in the demo pool, not every CVE an upload might contain. CVEs MSRC does not publish stay as an empty patch list.
- The PowerShell script checks the machine it runs on. It does not connect to the fictional hosts named in the comments.
- Live briefings have not yet been tested against a real model. No key is stored in the repo.
- On a public deployment the exceptions register lasts as long as the visitor's session. The CSV and JSON download are the portable copy.
- The overdue projection does not model findings that will become newly overdue. The chart says so.
- The overdue burn-down and the 7-day miss projection each spend the full recent close rate. They are alternative uses of the same capacity, not additive forecasts, and both captions say so.
- The 7-day window is `[as_of, as_of + 7]` inclusive, which is eight deadline dates. It matches the "Due soon" status (7 days or fewer left) used everywhere else.
- Open findings with no first-seen date (a Nessus-style export without that column) count in the cards but cannot be placed on the time charts. The charts say how many were left out.
- Interpretation to re-check against the directive text: a finding first seen before CISA lists its CVE in KEV starts its clock at first seen, so on the day it is listed it can already be past a short KEV deadline. That follows "whichever event occurs first," but CISA may read a change of decision path as restarting the clock.
- Uploads are parsed row by row. The upload limit is 10 MB (`.streamlit/config.toml`), which bounds parse time on a shared server.

## Next

- Publish the Monday note as a GitHub Issue or an RSS item. The Markdown download is the stand-in.
- If CISA publishes the generally-public-facing product list, replace `match_public_facing` with that list and drop the assumed flag for those rows.
- Bind the fact checker to the field a number came from, not merely to presence in the facts JSON.

## History

- **2026-10-16 — Live briefing key fallback removed (security fix).** Found in a read-through before the first deployment: the Briefing page fell back to a server-side key when the visitor left the field blank, while the API base URL was editable on the page. Deployed as the README instructed (key in Streamlit secrets), any visitor could have spent that key or sent it to their own server. Fixed as described under Briefings: visitor key only, endpoint from configuration only, https enforced before sending. Not exploitable before the fix in practice, because no key had been configured and the app had not been deployed. Verified: `ruff check .` clean; `python -m pytest -q` 97 passed on Python 3.12.12; the 5 new tests fail against the previous code.
- **2026-10-17 — Pre-publication review.** An independent read of the whole app before it went public found one high-severity issue and thirteen smaller ones, all fixed here. High: every visitor shared one exceptions file, so an anonymous visitor could add a register entry (rendered as Markdown, links included) or remove the seeded ones, changing what every later visitor saw and the overdue and SLO numbers; the register is now per-session, the file is opt-in, imports are capped, and free text renders as plain text. Medium: no upload size limit (now 10 MB, and the parse cache is bounded); live Vulnrichment lookups past the first 40 CVEs of an upload never ran, because already-cached results counted toward the limit, so it now resumes with the next batch; undated findings silently missing from the time charts; README and design-note figures that no longer matched the refreshed snapshot. Low: a malformed CSV showed a traceback; a host named like a blocked cmdlet (`wusa`) made the PowerShell audit refuse itself; scanner EPSS in scientific notation (`9.7e-05`) was read about 1,000 times too high; a closed row with no fix date counted as an SLO miss; uploads were labeled as the fictional estate in exports; grammar and label fixes. The same day, a wording edit made directly in the bundled demo CSV put an unquoted comma into the plugin-output column, which shifted every row by one column, so the demo loaded with zero findings. The file was rewritten with a real CSV writer (only that column differs from the generated file), and `tests/test_demo_data.py` now fails if any row's column count differs from the header or the demo stops parsing.
- **2026-10-17 — Living estate and the radar data block.** The bundled lab now moves forward one simulated day each morning instead of being regenerated (`kev_radar/evolve.py`, described under Living estate); the refresh job carries the estate's CVEs into the pool, `--estate-only` and `--rebuild` were added, the generator writes `\n` line endings on every OS, and day zero was built as of October 16 and advanced to October 17. The header gained a line for the lab's latest day and the radar rings new findings. The radar's native tooltips were replaced by the data block in `radar.js` after hover proved hard to use and did nothing on phones. The first wiring of the script ran nothing: Streamlit's DOMPurify pass deleted it because a comment contained `<body>`; a test now keeps that pattern out. Verified: `ruff check .` clean; `python -m pytest -q` 149 passed; a headless AppTest rendered all 10 pages with no errors; Playwright in Chrome confirmed hover, click-to-pin, Escape, arrow keys, a phone tap, and that the block closes when the SVG is replaced, with no page errors; the offline pace simulation is summarized under Living estate.
- **2026-10-18 — Enlarged radar view.** Requested so the radar is easier to read. Double-click, Enter, or the Enlarge radar button opens a full-screen copy (described under Theme). The first phone version showed the page through a translucent backdrop, swung the sweep off center once the viewBox was cropped, and clipped the side labels; the backdrop is now solid, the sweep's origin is pinned in user units, and folded side labels anchor inward. A first landscape-phone version came out smaller than the inline radar, which led to the compact short-screen layout. Verified: `ruff check .` clean; `python -m pytest -q` 150 passed; AppTest rendered all 10 pages with no errors; Playwright in Chrome confirmed double-click, the button, Enter, hover and arrow keys inside the view, Escape (block, then view), Close, backdrop and double-click closing, focus returning to the inline radar, and the view on a 390 × 844 phone (folded, 366 px) and an 844 × 390 phone (compact, 374 px), with no page errors. README screenshots were not retaken, so they still show the October 17 numbers the README quotes, without the Enlarge button.
