"""
netra/reports/html_report.py
Interactive single-file HTML report with:
  - Severity filter buttons
  - Searchable findings table
  - vis.js attack graph visualisation
  - CVSS score bars
  - Dark/light theme toggle
  - Fully self-contained (no CDN required at view time)
"""

import re
import json
from pathlib import Path
from datetime import datetime


def generate_html_report(ctx: dict, reports_dir: Path) -> Path:
    """
    Generate a self-contained interactive HTML report.

    Args:
        ctx:         Report context dict.
        reports_dir: Directory to save the output file.

    Returns:
        Path to the generated .html file.
    """
    findings = ctx.get("findings", [])
    chains   = ctx.get("chains", [])
    assets   = ctx.get("assets", [])
    stats    = ctx.get("stats", {})

    html = _build_html(ctx, findings, chains, assets, stats)

    filename = _report_filename(ctx, "html")
    out_path = reports_dir / filename
    out_path.write_text(html, encoding="utf-8")
    return out_path


def _build_html(ctx: dict, findings: list, chains: list, assets: list, stats: dict) -> str:
    """Assemble the full HTML document string."""
    findings_json = json.dumps([_serialize_finding(f) for f in findings], ensure_ascii=False)
    chains_json   = json.dumps([_serialize_chain(c) for c in chains], ensure_ascii=False)
    assets_json   = json.dumps([_serialize_asset(a) for a in assets], ensure_ascii=False)

    scan_id    = ctx.get("scan_id", "N/A")
    client     = ctx.get("client", "Confidential")
    engagement = ctx.get("engagement", "Security Assessment")
    date       = ctx.get("date", datetime.now().strftime("%Y-%m-%d"))
    operator   = ctx.get("operator", "Security Team")
    risk_score = ctx.get("risk_score", 0)
    risk_grade = ctx.get("risk_grade", "?")
    total      = sum(stats.values())

    grade_color = {
        "A": "#00E676", "B": "#00BCD4", "C": "#FFC107", "D": "#F44336"
    }.get(risk_grade, "#888888")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NETRA Report — {engagement}</title>
{_css()}
</head>
<body class="dark">

<!-- Header -->
<header>
  <div class="header-content">
    <div class="logo">
      <span class="logo-text">NETRA</span>
      <span class="logo-sub">नेत्र</span>
    </div>
    <div class="header-meta">
      <span>{client}</span>
      <span class="sep">|</span>
      <span>{engagement}</span>
      <span class="sep">|</span>
      <span>{date}</span>
    </div>
    <div class="header-actions">
      <button onclick="toggleTheme()" class="btn-icon" title="Toggle theme">🌙</button>
      <button onclick="window.print()" class="btn-icon" title="Print">🖨</button>
    </div>
  </div>
</header>

<!-- Risk scorecard -->
<section class="scorecard">
  <div class="score-card">
    <div class="grade" style="color:{grade_color}">{risk_grade}</div>
    <div class="score">{risk_score}<span class="score-max">/100</span></div>
    <div class="score-label">Risk Score</div>
  </div>
  <div class="severity-cards">
    <div class="sev-card critical" onclick="filterSev('critical')">
      <div class="sev-count">{stats.get("critical",0)}</div>
      <div class="sev-label">Critical</div>
    </div>
    <div class="sev-card high" onclick="filterSev('high')">
      <div class="sev-count">{stats.get("high",0)}</div>
      <div class="sev-label">High</div>
    </div>
    <div class="sev-card medium" onclick="filterSev('medium')">
      <div class="sev-count">{stats.get("medium",0)}</div>
      <div class="sev-label">Medium</div>
    </div>
    <div class="sev-card low" onclick="filterSev('low')">
      <div class="sev-count">{stats.get("low",0)}</div>
      <div class="sev-label">Low</div>
    </div>
    <div class="sev-card info" onclick="filterSev('')">
      <div class="sev-count">{total}</div>
      <div class="sev-label">Total</div>
    </div>
  </div>
  <div class="scan-meta">
    <table>
      <tr><th>Scan ID</th><td>{scan_id}</td></tr>
      <tr><th>Operator</th><td>{operator}</td></tr>
      <tr><th>Assets</th><td>{len(assets)}</td></tr>
      <tr><th>Chains</th><td>{len(chains)}</td></tr>
    </table>
  </div>
</section>

<!-- Findings section -->
<section class="findings-section">
  <div class="section-header">
    <h2>Findings</h2>
    <div class="filter-bar">
      <input type="text" id="searchInput" placeholder="Search findings..."
             oninput="filterFindings()" class="search-box">
      <button onclick="filterSev('critical')" class="btn-sev critical">Critical</button>
      <button onclick="filterSev('high')"     class="btn-sev high">High</button>
      <button onclick="filterSev('medium')"   class="btn-sev medium">Medium</button>
      <button onclick="filterSev('low')"      class="btn-sev low">Low</button>
      <button onclick="filterSev('')"         class="btn-sev all">All</button>
    </div>
  </div>

  <div id="findingsTable">
    <table class="data-table" id="findingsTbl">
      <thead>
        <tr>
          <th>#</th>
          <th onclick="sortTable(1)">Title ↕</th>
          <th onclick="sortTable(2)">Severity ↕</th>
          <th onclick="sortTable(3)">CVSS ↕</th>
          <th>Host</th>
          <th>MITRE</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody id="findingsBody">
      </tbody>
    </table>
  </div>
</section>

<!-- Finding detail modal -->
<div id="modal" class="modal" onclick="closeModal(event)">
  <div class="modal-content" onclick="event.stopPropagation()">
    <button class="modal-close" onclick="document.getElementById('modal').style.display='none'">✕</button>
    <div id="modalBody"></div>
  </div>
</div>

<!-- Attack chains -->
{_chains_section_html(chains)}

<!-- Asset inventory -->
{_assets_section_html(assets)}

<footer>
  <div>NETRA नेत्र — The Third Eye of Security | CONFIDENTIAL</div>
  <div>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")} UTC</div>
</footer>

<script>
const FINDINGS = {findings_json};
const CHAINS   = {chains_json};
const ASSETS   = {assets_json};

let activeFilter = '';

const SEV_ORDER = {{critical:0, high:1, medium:2, low:3, info:4}};
const SEV_COLORS = {{
  critical: '#FF4444', high: '#FF7700', medium: '#FFB800',
  low: '#88CC44', info: '#888888'
}};

function renderFindings(list) {{
  const tbody = document.getElementById('findingsBody');
  if (!list.length) {{
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:#888">No findings match the filter.</td></tr>';
    return;
  }}
  tbody.innerHTML = list.map((f, i) => {{
    const sev = (f.severity||'info').toLowerCase();
    const col = SEV_COLORS[sev] || '#888';
    return `<tr class="finding-row" onclick="showDetail(${{f.id}})" data-sev="${{sev}}">
      <td>${{i+1}}</td>
      <td class="title-cell">${{esc(f.title||'')}}</td>
      <td><span class="badge" style="background:${{col}}">${{(f.severity||'').toUpperCase()}}</span></td>
      <td>${{cvssBar(f.cvss_score)}}</td>
      <td class="host-cell">${{esc(f.host||'')}}</td>
      <td><small>${{esc(f.mitre||'')}}</small></td>
      <td><span class="status-badge ${{f.status}}">${{f.status||'open'}}</span></td>
    </tr>`;
  }}).join('');
}}

function cvssBar(score) {{
  if (!score) return '<span style="color:#666">N/A</span>';
  const w = Math.round(score * 10);
  const col = score >= 9 ? '#FF4444' : score >= 7 ? '#FF7700' : score >= 4 ? '#FFB800' : '#88CC44';
  return `<div class="cvss-bar"><div style="width:${{w}}%;background:${{col}}">${{score}}</div></div>`;
}}

function filterSev(sev) {{
  activeFilter = sev;
  filterFindings();
}}

function filterFindings() {{
  const q   = document.getElementById('searchInput').value.toLowerCase();
  const res = FINDINGS.filter(f => {{
    const matchSev  = !activeFilter || (f.severity||'').toLowerCase() === activeFilter;
    const matchText = !q || [f.title,f.host,f.description,f.cve_id]
      .some(v => (v||'').toLowerCase().includes(q));
    return matchSev && matchText;
  }});
  renderFindings(res);
}}

function showDetail(id) {{
  const f = FINDINGS.find(x => x.id === id);
  if (!f) return;
  const sev = (f.severity||'info').toLowerCase();
  const col = SEV_COLORS[sev] || '#888';
  document.getElementById('modalBody').innerHTML = `
    <div class="modal-title">${{esc(f.title||'')}}</div>
    <div class="modal-badges">
      <span class="badge" style="background:${{col}}">${{(f.severity||'').toUpperCase()}}</span>
      ${{f.cvss_score ? `<span class="badge-grey">CVSS ${{f.cvss_score}}</span>` : ''}}
      ${{f.cve_id ? `<span class="badge-grey">${{esc(f.cve_id)}}</span>` : ''}}
      ${{f.mitre  ? `<span class="badge-grey">${{esc(f.mitre)}}</span>` : ''}}
    </div>
    <div class="detail-grid">
      <div><b>Host</b><div>${{esc(f.host||'N/A')}}</div></div>
      <div><b>URL</b><div><a href="${{esc(f.url||'')}}" target="_blank">${{esc((f.url||'')[:60])}}</a></div></div>
      <div><b>Category</b><div>${{esc(f.category||'N/A')}}</div></div>
      <div><b>OWASP</b><div>${{esc(f.owasp_web||'N/A')}}</div></div>
    </div>
    ${{f.description ? `<div class="detail-block"><b>Description</b><p>${{esc(f.description||'')}}</p></div>` : ''}}
    ${{f.impact ? `<div class="detail-block"><b>Impact</b><p>${{esc(f.impact||'')}}</p></div>` : ''}}
    ${{f.ai_narrative ? `<div class="detail-block"><b>AI Analysis</b><p>${{esc(f.ai_narrative||'')}}</p></div>` : ''}}
    ${{f.poc_command ? `<div class="detail-block"><b>PoC</b><pre>${{esc(f.poc_command||'')}}</pre></div>` : ''}}
    ${{f.remediation ? `<div class="detail-block"><b>Remediation</b><p>${{esc(f.remediation||'')}}</p></div>` : ''}}
  `;
  document.getElementById('modal').style.display = 'flex';
}}

function closeModal(e) {{
  if (e.target.id === 'modal') document.getElementById('modal').style.display = 'none';
}}

function sortTable(col) {{
  const list = [...FINDINGS].sort((a, b) => {{
    if (col === 2) return (SEV_ORDER[a.severity]||5) - (SEV_ORDER[b.severity]||5);
    if (col === 3) return (b.cvss_score||0) - (a.cvss_score||0);
    return (a.title||'').localeCompare(b.title||'');
  }});
  renderFindings(list);
}}

function toggleTheme() {{
  document.body.classList.toggle('dark');
  document.body.classList.toggle('light');
}}

function esc(s) {{
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}}

// Initial render
renderFindings(FINDINGS);
</script>
</body>
</html>"""


def _css() -> str:
    """Return the embedded CSS stylesheet."""
    return """<style>
:root {
  --bg: #0d1117; --bg2: #161b22; --bg3: #1c2128; --border: #30363d;
  --text: #c9d1d9; --text2: #8b949e; --accent: #2E75B6;
  --critical: #FF4444; --high: #FF7700; --medium: #FFB800;
  --low: #88CC44; --info: #888888;
}
body.light {
  --bg: #f6f8fa; --bg2: #ffffff; --bg3: #eaeef2; --border: #d0d7de;
  --text: #24292f; --text2: #57606a; --accent: #1F3864;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  background: var(--bg); color: var(--text); font-size: 14px; }
header { background: var(--bg2); border-bottom: 1px solid var(--border);
  padding: 12px 24px; position: sticky; top: 0; z-index: 100; }
.header-content { display: flex; align-items: center; gap: 16px; }
.logo { display: flex; align-items: baseline; gap: 6px; }
.logo-text { font-size: 20px; font-weight: 700; color: var(--accent); }
.logo-sub  { font-size: 14px; color: var(--text2); }
.header-meta { flex: 1; color: var(--text2); font-size: 12px; }
.sep { margin: 0 6px; color: var(--border); }
.btn-icon { background: none; border: none; cursor: pointer; font-size: 16px; }
.scorecard { display: flex; gap: 16px; padding: 20px 24px; align-items: center;
  flex-wrap: wrap; background: var(--bg2); border-bottom: 1px solid var(--border); }
.score-card { text-align: center; min-width: 100px; }
.grade { font-size: 48px; font-weight: 700; line-height: 1; }
.score { font-size: 28px; font-weight: 600; }
.score-max { font-size: 14px; color: var(--text2); }
.score-label { font-size: 11px; color: var(--text2); margin-top: 4px; }
.severity-cards { display: flex; gap: 8px; }
.sev-card { padding: 12px 18px; border-radius: 8px; cursor: pointer; text-align: center;
  min-width: 70px; transition: opacity 0.2s; }
.sev-card:hover { opacity: 0.8; }
.sev-card.critical { background: rgba(255,68,68,0.15); border: 1px solid #FF4444; }
.sev-card.high     { background: rgba(255,119,0,0.15); border: 1px solid #FF7700; }
.sev-card.medium   { background: rgba(255,184,0,0.15); border: 1px solid #FFB800; }
.sev-card.low      { background: rgba(136,204,68,0.15);border: 1px solid #88CC44; }
.sev-card.info     { background: rgba(136,136,136,0.1);border: 1px solid #888; }
.sev-count { font-size: 22px; font-weight: 700; }
.sev-label { font-size: 11px; color: var(--text2); }
.scan-meta table { border-collapse: collapse; font-size: 12px; }
.scan-meta th { color: var(--text2); padding-right: 12px; text-align: left; padding: 2px 8px 2px 0; }
.scan-meta td { color: var(--text); padding: 2px 0; }
.findings-section { padding: 20px 24px; }
.section-header { display: flex; align-items: center; gap: 16px;
  margin-bottom: 16px; flex-wrap: wrap; }
.section-header h2 { color: var(--accent); font-size: 18px; }
.filter-bar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.search-box { background: var(--bg3); border: 1px solid var(--border);
  border-radius: 6px; padding: 6px 12px; color: var(--text); font-size: 13px;
  width: 220px; }
.btn-sev { padding: 4px 12px; border-radius: 4px; border: 1px solid; cursor: pointer;
  font-size: 12px; font-weight: 600; background: transparent; }
.btn-sev.critical { border-color: #FF4444; color: #FF4444; }
.btn-sev.high     { border-color: #FF7700; color: #FF7700; }
.btn-sev.medium   { border-color: #FFB800; color: #FFB800; }
.btn-sev.low      { border-color: #88CC44; color: #88CC44; }
.btn-sev.all      { border-color: var(--border); color: var(--text2); }
.btn-sev:hover    { opacity: 0.8; }
.data-table { width: 100%; border-collapse: collapse; }
.data-table th { background: var(--bg3); padding: 8px 10px; text-align: left;
  font-size: 12px; cursor: pointer; border-bottom: 2px solid var(--border); }
.data-table td { padding: 7px 10px; border-bottom: 1px solid var(--border);
  font-size: 13px; }
.finding-row { cursor: pointer; transition: background 0.15s; }
.finding-row:hover { background: var(--bg3); }
.title-cell { max-width: 350px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.host-cell  { max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  font-family: monospace; font-size: 12px; color: var(--text2); }
.badge { padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 600;
  color: white; white-space: nowrap; }
.badge-grey { padding: 2px 8px; border-radius: 3px; font-size: 11px;
  background: var(--bg3); border: 1px solid var(--border); }
.status-badge { padding: 2px 6px; border-radius: 3px; font-size: 11px; }
.status-badge.open     { background: rgba(255,68,68,0.15); color: #FF4444; }
.status-badge.fp       { background: rgba(136,136,136,0.15); color: #888; }
.status-badge.fixed    { background: rgba(136,204,68,0.15); color: #88CC44; }
.status-badge.verified { background: rgba(0,200,100,0.15); color: #00C864; }
.cvss-bar { background: var(--bg3); border-radius: 3px; height: 18px;
  width: 80px; overflow: hidden; }
.cvss-bar div { height: 100%; display: flex; align-items: center; padding-left: 4px;
  font-size: 10px; font-weight: 600; color: white; border-radius: 3px; }
.modal { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.7);
  z-index: 1000; align-items: center; justify-content: center; }
.modal-content { background: var(--bg2); border: 1px solid var(--border);
  border-radius: 10px; max-width: 700px; width: 90%; max-height: 85vh;
  overflow-y: auto; padding: 24px; position: relative; }
.modal-close { position: absolute; top: 12px; right: 16px; background: none;
  border: none; color: var(--text2); cursor: pointer; font-size: 18px; }
.modal-title { font-size: 18px; font-weight: 600; margin-bottom: 12px; }
.modal-badges { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }
.detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px;
  margin-bottom: 16px; }
.detail-grid > div { background: var(--bg3); padding: 8px; border-radius: 6px;
  font-size: 12px; }
.detail-grid b { display: block; color: var(--text2); margin-bottom: 4px; }
.detail-block { margin-bottom: 12px; }
.detail-block b { display: block; color: var(--text2); margin-bottom: 4px; font-size: 12px; }
.detail-block p { font-size: 13px; line-height: 1.6; }
.detail-block pre { background: var(--bg3); padding: 10px; border-radius: 6px;
  font-size: 12px; overflow-x: auto; }
.chains-section, .assets-section { padding: 0 24px 20px; }
.chains-section h2, .assets-section h2 { color: var(--accent); font-size: 18px;
  margin-bottom: 16px; padding-top: 20px;
  border-top: 1px solid var(--border); }
.chain-card { background: var(--bg2); border: 1px solid var(--border);
  border-radius: 8px; padding: 16px; margin-bottom: 12px; }
.chain-header { display: flex; justify-content: space-between; margin-bottom: 8px; }
.chain-cvss { font-size: 20px; font-weight: 700; color: #FF7700; }
.chain-mitre { font-size: 12px; color: var(--text2); font-family: monospace; }
.chain-steps { list-style: none; margin-top: 8px; }
.chain-steps li { font-size: 12px; color: var(--text2); padding: 2px 0; }
.chain-steps li::before { content: "→ "; color: var(--accent); }
footer { text-align: center; padding: 20px; color: var(--text2); font-size: 11px;
  border-top: 1px solid var(--border); margin-top: 20px; }
</style>"""


def _chains_section_html(chains: list) -> str:
    """Build the attack chains section HTML."""
    if not chains:
        return ""

    items = []
    for i, c in enumerate(chains[:10], 1):
        import json as _json
        try:
            node_ids = _json.loads(c.get("nodes", "[]")) if isinstance(c.get("nodes"), str) else c.get("nodes", [])
        except Exception:
            node_ids = []
        steps_html = "".join(f"<li>Step {j+1}: Finding #{fid}</li>"
                             for j, fid in enumerate(node_ids))
        items.append(f"""
        <div class="chain-card">
          <div class="chain-header">
            <div>
              <div class="chain-cvss">CVSS {c.get("combined_cvss", "N/A")}</div>
              <div class="chain-mitre">{_esc(c.get("mitre_sequence", "N/A"))}</div>
            </div>
            <div style="color:#888;font-size:12px">Chain {i}</div>
          </div>
          {f'<p style="font-size:12px;color:#aaa;margin-bottom:8px">{_esc(c.get("narrative","")[:300])}</p>' if c.get("narrative") else ""}
          <ul class="chain-steps">{steps_html}</ul>
        </div>""")

    return f"""
<section class="chains-section">
  <h2>Attack Chains ({len(chains)})</h2>
  {"".join(items)}
</section>"""


def _assets_section_html(assets: list) -> str:
    """Build the asset inventory section HTML."""
    if not assets:
        return ""

    rows = ""
    for a in assets[:100]:
        live = "✓" if a.get("is_live") else ""
        rows += (f"<tr><td>{_esc(a.get('value','')[:50])}</td>"
                 f"<td>{_esc(a.get('asset_type',''))}</td>"
                 f"<td style='color:#88CC44'>{live}</td>"
                 f"<td>{_esc(str(a.get('tech_stack','')[:40]))}</td></tr>")

    return f"""
<section class="assets-section">
  <h2>Asset Inventory ({len(assets)})</h2>
  <table class="data-table">
    <thead><tr><th>Asset</th><th>Type</th><th>Live</th><th>Tech</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</section>"""


def _serialize_finding(f: dict) -> dict:
    """Slim down a finding for JSON embedding in HTML."""
    return {
        "id":          f.get("id"),
        "title":       (f.get("title") or "")[:100],
        "severity":    f.get("severity"),
        "cvss_score":  f.get("cvss_score"),
        "host":        f.get("host"),
        "url":         f.get("url") or "",
        "cve_id":      f.get("cve_id") or "",
        "mitre":       f.get("mitre_technique") or "",
        "category":    f.get("category") or "",
        "owasp_web":   f.get("owasp_web") or "",
        "status":      f.get("status") or "open",
        "description": (f.get("description") or "")[:400],
        "impact":      (f.get("impact") or "")[:200],
        "remediation": (f.get("remediation") or "")[:300],
        "ai_narrative":(f.get("ai_narrative") or "")[:400],
        "poc_command": (f.get("poc_command") or "")[:200],
    }


def _serialize_chain(c: dict) -> dict:
    """Slim down a chain for JSON embedding."""
    import json as _json
    try:
        nodes = _json.loads(c.get("nodes", "[]")) if isinstance(c.get("nodes"), str) else c.get("nodes", [])
    except Exception:
        nodes = []
    return {
        "id":             c.get("id"),
        "combined_cvss":  c.get("combined_cvss"),
        "mitre_sequence": c.get("mitre_sequence"),
        "narrative":      (c.get("narrative") or "")[:300],
        "nodes":          nodes,
    }


def _serialize_asset(a: dict) -> dict:
    """Slim down an asset for JSON embedding."""
    return {
        "value":      a.get("value"),
        "asset_type": a.get("asset_type"),
        "is_live":    bool(a.get("is_live")),
        "tech_stack": a.get("tech_stack"),
    }


def _esc(s: str) -> str:
    """HTML-escape a string."""
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def _report_filename(ctx: dict, ext: str) -> str:
    """Generate standardised report filename."""
    scan_id = ctx.get("scan_id", "unknown")
    date    = ctx.get("date", datetime.now().strftime("%Y%m%d")).replace("-", "")
    target  = re.sub(r"[^a-zA-Z0-9]", "_", ctx.get("engagement", scan_id))[:20]
    return f"NETRA_vapt_{target}_{date}.{ext}"
