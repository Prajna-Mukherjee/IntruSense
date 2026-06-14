import React, { useState } from 'react';

const API_URL = 'http://localhost:8000';

const C = {
  bg: '#0a0e1a', card: '#0f1829', border: '#1e3a5f',
  accent: '#60a5fa', red: '#ef4444', orange: '#f59e0b',
  green: '#22c55e', purple: '#a78bfa', text: '#e2e8f0',
  muted: '#64748b', subtle: '#94a3b8',
};

function severityFromScore(score) {
  if (score > 0.85) return 'Critical';
  if (score > 0.7)  return 'High';
  if (score > 0.4)  return 'Medium';
  return 'Low';
}

function severityColor(s) {
  return { Critical: '#dc2626', High: '#ea580c', Medium: '#ca8a04', Low: '#16a34a' }[s] || '#64748b';
}

function formatTs(ts) {
  if (!ts) return '—';
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}

function generateHTML(logs, stats, userName) {
  const now        = new Date();
  const reportId   = `ISR-${now.getFullYear()}${String(now.getMonth()+1).padStart(2,'0')}${String(now.getDate()).padStart(2,'0')}-${Math.floor(Math.random()*9000+1000)}`;
  const threats    = logs.filter(l => l.is_threat);
  const benign     = logs.filter(l => !l.is_threat);
  const detRate    = stats.total_logs > 0 ? ((stats.total_threats / stats.total_logs) * 100).toFixed(1) : '0.0';

  // Attack distribution
  const attackCounts = {};
  threats.forEach(l => {
    const k = l.attack_type || 'Unknown';
    attackCounts[k] = (attackCounts[k] || 0) + 1;
  });
  const attackRows = Object.entries(attackCounts)
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => ({ name, count, pct: ((count / (threats.length || 1)) * 100).toFixed(1) }));

  // Severity breakdown
  const sevCounts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  threats.forEach(l => { sevCounts[severityFromScore(l.threat_score || 0)]++; });

  // Top MITRE tactics
  const tacticCounts = {};
  threats.forEach(l => {
    const t = l.mitre?.tactic || l.mitre_tactic;
    if (t) tacticCounts[t] = (tacticCounts[t] || 0) + 1;
  });
  const topTactics = Object.entries(tacticCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);

  // Recent threat rows (top 20)
  const recentThreats = [...threats]
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, 20);

  const sevBadge = (s) => `<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:.5px;background:${severityColor(s)}22;color:${severityColor(s)};border:1px solid ${severityColor(s)}44">${s}</span>`;

  const barChart = (items, total) => items.map(({ name, count, pct }) => `
    <div style="margin-bottom:10px">
      <div style="display:flex;justify-content:space-between;margin-bottom:4px">
        <span style="font-size:12px;color:#334155;font-family:'JetBrains Mono',monospace">${name}</span>
        <span style="font-size:12px;color:#1e40af;font-weight:700">${count} <span style="color:#94a3b8;font-weight:400">(${pct}%)</span></span>
      </div>
      <div style="height:6px;background:#e2e8f0;border-radius:3px;overflow:hidden">
        <div style="height:100%;width:${pct}%;background:linear-gradient(90deg,#1d4ed8,#3b82f6);border-radius:3px"></div>
      </div>
    </div>`).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>IntruSense Audit Report · ${reportId}</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&family=Orbitron:wght@700&display=swap" rel="stylesheet"/>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:'Inter',sans-serif;background:#f8fafc;color:#0f172a;font-size:13px;line-height:1.6}
  .page{max-width:900px;margin:0 auto;padding:40px 48px}

  /* ── Cover ── */
  .cover{background:linear-gradient(135deg,#0f172a 0%,#1e3a5f 60%,#0f172a 100%);color:#fff;padding:60px 48px;position:relative;overflow:hidden;page-break-after:always}
  .cover::before{content:'';position:absolute;top:-80px;right:-80px;width:400px;height:400px;border-radius:50%;background:rgba(96,165,250,.07);pointer-events:none}
  .cover::after{content:'';position:absolute;bottom:-60px;left:-60px;width:300px;height:300px;border-radius:50%;background:rgba(167,139,250,.06);pointer-events:none}
  .cover-logo{font-family:'Orbitron',sans-serif;font-size:11px;letter-spacing:4px;color:#60a5fa;text-transform:uppercase;margin-bottom:40px}
  .cover-title{font-family:'Orbitron',sans-serif;font-size:32px;font-weight:700;color:#fff;line-height:1.2;margin-bottom:8px}
  .cover-sub{font-size:14px;color:#94a3b8;margin-bottom:48px}
  .cover-meta{display:grid;grid-template-columns:1fr 1fr;gap:24px;border-top:1px solid rgba(255,255,255,.1);padding-top:32px}
  .cover-meta-item label{display:block;font-size:10px;letter-spacing:1px;text-transform:uppercase;color:#64748b;margin-bottom:4px}
  .cover-meta-item span{font-size:13px;color:#e2e8f0;font-family:'JetBrains Mono',monospace}
  .classification{display:inline-block;padding:4px 14px;border:1px solid #ef4444;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:2px;color:#ef4444;text-transform:uppercase;margin-bottom:20px}

  /* ── Sections ── */
  .section{margin-bottom:40px}
  .section-title{font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;color:#1d4ed8;border-bottom:2px solid #1d4ed8;padding-bottom:8px;margin-bottom:20px;display:flex;align-items:center;gap:8px}
  .section-title::before{content:'';display:inline-block;width:3px;height:14px;background:#1d4ed8;border-radius:2px}

  /* ── KPI grid ── */
  .kpi-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}
  .kpi{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:16px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,.05)}
  .kpi-value{font-size:28px;font-weight:700;color:#0f172a;font-family:'JetBrains Mono',monospace;line-height:1}
  .kpi-label{font-size:10px;color:#64748b;letter-spacing:.5px;text-transform:uppercase;margin-top:6px}
  .kpi-dot{width:6px;height:6px;border-radius:50%;margin:8px auto 0}

  /* ── Two-col layout ── */
  .two-col{display:grid;grid-template-columns:1fr 1fr;gap:20px}

  /* ── Card ── */
  .card{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:20px;box-shadow:0 1px 3px rgba(0,0,0,.05)}
  .card h3{font-size:11px;font-weight:700;letter-spacing:.5px;text-transform:uppercase;color:#475569;margin-bottom:14px}

  /* ── Severity grid ── */
  .sev-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
  .sev-card{padding:14px;border-radius:6px;text-align:center}
  .sev-count{font-size:24px;font-weight:700;font-family:'JetBrains Mono',monospace}
  .sev-label{font-size:10px;letter-spacing:.5px;text-transform:uppercase;margin-top:4px;opacity:.8}

  /* ── Table ── */
  table{width:100%;border-collapse:collapse;font-size:11px}
  thead tr{background:#f1f5f9}
  th{padding:8px 10px;text-align:left;font-weight:600;color:#475569;letter-spacing:.3px;text-transform:uppercase;font-size:10px;border-bottom:2px solid #e2e8f0}
  td{padding:7px 10px;border-bottom:1px solid #f1f5f9;color:#334155;vertical-align:middle}
  tr:last-child td{border-bottom:none}
  tr:nth-child(even){background:#fafafa}
  .mono{font-family:'JetBrains Mono',monospace;font-size:10px}

  /* ── Tactic row ── */
  .tactic-row{display:flex;align-items:center;gap:10px;margin-bottom:8px}
  .tactic-bar-bg{flex:1;height:8px;background:#f1f5f9;border-radius:4px;overflow:hidden}
  .tactic-bar{height:100%;background:linear-gradient(90deg,#7c3aed,#a78bfa);border-radius:4px}

  /* ── Footer ── */
  .footer{border-top:1px solid #e2e8f0;padding-top:20px;margin-top:40px;display:flex;justify-content:space-between;align-items:center;color:#94a3b8;font-size:10px}
  .footer-logo{font-family:'Orbitron',sans-serif;font-size:9px;letter-spacing:2px;color:#1d4ed8}

  /* ── Print ── */
  @media print{
    body{background:#fff}
    .page{padding:20px 32px}
    .cover{page-break-after:always}
    .no-print{display:none!important}
    .section{page-break-inside:avoid}
  }

  /* ── Download btn ── */
  .dl-btn{position:fixed;top:20px;right:20px;background:#1d4ed8;color:#fff;border:none;padding:10px 20px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;box-shadow:0 4px 12px rgba(29,78,216,.4);display:flex;align-items:center;gap:8px;font-family:'Inter',sans-serif;z-index:999}
  .dl-btn:hover{background:#1e40af}
</style>
</head>
<body>

<button class="dl-btn no-print" onclick="window.print()">🖨️ Save as PDF</button>

<!-- ══ COVER PAGE ══════════════════════════════════════════════════════════════ -->
<div class="cover page">
  <div class="cover-logo">🛡️ &nbsp; IntruSense · AI Threat Detection Platform</div>
  <div class="classification">Confidential</div>
  <div class="cover-title">Security Audit Report</div>
  <div class="cover-sub">AI-Powered Network Intrusion Detection &amp; Analysis</div>

  <div class="cover-meta">
    <div class="cover-meta-item"><label>Report ID</label><span>${reportId}</span></div>
    <div class="cover-meta-item"><label>Generated</label><span>${now.toLocaleString()}</span></div>
    <div class="cover-meta-item"><label>Analyst</label><span>${userName || 'System'}</span></div>
    <div class="cover-meta-item"><label>Log Period</label><span>${logs.length > 0 ? formatTs(logs[logs.length-1]?.timestamp) + ' → ' + formatTs(logs[0]?.timestamp) : 'N/A'}</span></div>
    <div class="cover-meta-item"><label>Total Events</label><span>${stats.total_logs.toLocaleString()}</span></div>
    <div class="cover-meta-item"><label>Threat Detection Rate</label><span>${detRate}%</span></div>
  </div>
</div>

<!-- ══ BODY ════════════════════════════════════════════════════════════════════ -->
<div class="page">

  <!-- Executive Summary -->
  <div class="section">
    <div class="section-title">Executive Summary</div>
    <p style="color:#334155;line-height:1.8;margin-bottom:16px">
      This report summarises the results of automated AI-driven analysis performed by the IntruSense platform
      on <strong>${stats.total_logs.toLocaleString()} network log events</strong>.
      The analysis employed an ensemble of XGBoost classification, Isolation Forest anomaly detection,
      and autoencoder-based reconstruction error scoring, cross-referenced against the MITRE ATT&amp;CK framework.
    </p>
    <p style="color:#334155;line-height:1.8">
      Of the events analysed, <strong style="color:#dc2626">${stats.total_threats.toLocaleString()} were classified as threats</strong>
      (${detRate}% detection rate) and <strong style="color:#16a34a">${benign.length.toLocaleString()} were benign</strong>.
      ${attackRows.length > 0 ? `The most prevalent threat category was <strong>${attackRows[0]?.name}</strong>, accounting for ${attackRows[0]?.pct}% of all detected threats.` : ''}
    </p>
  </div>

  <!-- KPI Strip -->
  <div class="section">
    <div class="section-title">Key Metrics</div>
    <div class="kpi-grid">
      <div class="kpi">
        <div class="kpi-value">${stats.total_logs.toLocaleString()}</div>
        <div class="kpi-dot" style="background:#60a5fa"></div>
        <div class="kpi-label">Total Events</div>
      </div>
      <div class="kpi">
        <div class="kpi-value" style="color:#dc2626">${stats.total_threats.toLocaleString()}</div>
        <div class="kpi-dot" style="background:#dc2626"></div>
        <div class="kpi-label">Threats Detected</div>
      </div>
      <div class="kpi">
        <div class="kpi-value" style="color:#16a34a">${benign.length.toLocaleString()}</div>
        <div class="kpi-dot" style="background:#16a34a"></div>
        <div class="kpi-label">Benign Events</div>
      </div>
      <div class="kpi">
        <div class="kpi-value" style="color:#ea580c">${detRate}%</div>
        <div class="kpi-dot" style="background:#ea580c"></div>
        <div class="kpi-label">Detection Rate</div>
      </div>
    </div>
  </div>

  <!-- Severity + Attack Distribution -->
  <div class="section">
    <div class="section-title">Threat Severity Breakdown</div>
    <div class="sev-grid">
      ${[
        { s: 'Critical', bg: '#fef2f2', c: '#dc2626' },
        { s: 'High',     bg: '#fff7ed', c: '#ea580c' },
        { s: 'Medium',   bg: '#fefce8', c: '#ca8a04' },
        { s: 'Low',      bg: '#f0fdf4', c: '#16a34a' },
      ].map(({ s, bg, c }) => `
        <div class="sev-card" style="background:${bg};border:1px solid ${c}22">
          <div class="sev-count" style="color:${c}">${sevCounts[s]}</div>
          <div class="sev-label" style="color:${c}">${s}</div>
        </div>`).join('')}
    </div>
  </div>

  <!-- Two-col: Attack types + MITRE tactics -->
  <div class="section">
    <div class="section-title">Attack &amp; Tactic Analysis</div>
    <div class="two-col">
      <div class="card">
        <h3>Attack Type Distribution</h3>
        ${attackRows.length > 0 ? barChart(attackRows, threats.length) : '<p style="color:#94a3b8;font-size:12px">No threats recorded.</p>'}
      </div>
      <div class="card">
        <h3>Top MITRE ATT&amp;CK Tactics</h3>
        ${topTactics.length > 0 ? topTactics.map(([tactic, count]) => `
          <div class="tactic-row">
            <span style="font-size:11px;color:#334155;min-width:100px">${tactic}</span>
            <div class="tactic-bar-bg"><div class="tactic-bar" style="width:${(count/topTactics[0][1]*100).toFixed(0)}%"></div></div>
            <span style="font-size:11px;font-weight:700;color:#7c3aed;min-width:24px;text-align:right">${count}</span>
          </div>`).join('') : '<p style="color:#94a3b8;font-size:12px">No MITRE data recorded.</p>'}
      </div>
    </div>
  </div>

  <!-- Recent Threats Table -->
  <div class="section">
    <div class="section-title">Recent Threat Events (Top 20)</div>
    <div class="card" style="padding:0;overflow:hidden">
      ${recentThreats.length > 0 ? `
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Attack Type</th>
            <th>Severity</th>
            <th>Threat Score</th>
            <th>Confidence</th>
            <th>MITRE ID</th>
            <th>Tactic</th>
          </tr>
        </thead>
        <tbody>
          ${recentThreats.map(l => {
            const sev = severityFromScore(l.threat_score || 0);
            return `<tr>
              <td class="mono">${formatTs(l.timestamp)}</td>
              <td style="color:#dc2626;font-weight:600">${l.attack_type || '—'}</td>
              <td>${sevBadge(sev)}</td>
              <td class="mono">${l.threat_score !== undefined ? (l.threat_score * 100).toFixed(0) + '%' : '—'}</td>
              <td class="mono">${l.confidence !== undefined ? (l.confidence * 100).toFixed(0) + '%' : '—'}</td>
              <td class="mono" style="color:#1d4ed8">${l.mitre?.technique_id || l.mitre_technique_id || '—'}</td>
              <td>${l.mitre?.tactic || l.mitre_tactic || '—'}</td>
            </tr>`;
          }).join('')}
        </tbody>
      </table>` : '<p style="padding:20px;color:#94a3b8">No threat events to display.</p>'}
    </div>
  </div>

  <!-- All Logs Summary Table -->
  <div class="section">
    <div class="section-title">Complete Log Summary (Last ${Math.min(logs.length, 50)} Events)</div>
    <div class="card" style="padding:0;overflow:hidden">
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Status</th>
            <th>Attack Type</th>
            <th>Threat Score</th>
            <th>MITRE ID</th>
          </tr>
        </thead>
        <tbody>
          ${[...logs].sort((a,b) => new Date(b.timestamp)-new Date(a.timestamp)).slice(0, 50).map(l => `
          <tr>
            <td class="mono">${formatTs(l.timestamp)}</td>
            <td>${l.is_threat
              ? '<span style="color:#dc2626;font-weight:700;font-size:10px">⚠ THREAT</span>'
              : '<span style="color:#16a34a;font-weight:700;font-size:10px">✓ CLEAN</span>'}</td>
            <td style="color:${l.is_threat ? '#dc2626' : '#475569'}">${l.attack_type || 'Benign'}</td>
            <td class="mono">${l.threat_score !== undefined ? (l.threat_score*100).toFixed(0)+'%' : '—'}</td>
            <td class="mono" style="color:#1d4ed8">${l.mitre?.technique_id || l.mitre_technique_id || '—'}</td>
          </tr>`).join('')}
        </tbody>
      </table>
    </div>
  </div>

  <!-- Footer -->
  <div class="footer">
    <div>
      <div class="footer-logo">IntruSense AI NIDS</div>
      <div style="margin-top:2px">Generated automatically · ${now.toISOString()}</div>
    </div>
    <div style="text-align:right">
      <div>Report ID: <span style="font-family:'JetBrains Mono',monospace">${reportId}</span></div>
      <div style="margin-top:2px">Confidential — Authorised Personnel Only</div>
    </div>
  </div>

</div>
</body>
</html>`;
}

export default function AuditReport({ authHeaders = {} }) {
  const [generating, setGenerating] = useState(false);
  const [error, setError]           = useState('');

  const handleGenerate = async () => {
    setGenerating(true);
    setError('');
    try {
      const userName = sessionStorage.getItem('intrusense_name') || '';
      const [logsRes, statsRes] = await Promise.all([
        fetch(`${API_URL}/api/logs?size=500`, { headers: authHeaders }),
        fetch(`${API_URL}/api/stats`,         { headers: authHeaders }),
      ]);
      if (!logsRes.ok || !statsRes.ok) throw new Error('Failed to fetch data');

      const logsData  = await logsRes.json();
      const statsData = await statsRes.json();
      const logs      = logsData.logs || [];

      const html = generateHTML(logs, statsData, userName);
      const blob = new Blob([html], { type: 'text/html' });
      const url  = URL.createObjectURL(blob);

      const a    = document.createElement('a');
      a.href     = url;
      a.download = `IntruSense-Audit-Report-${new Date().toISOString().slice(0,10)}.html`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (e) {
      setError('Failed to generate report. Is the backend running?');
    }
    setGenerating(false);
  };

  return (
    <div>
      <button
        onClick={handleGenerate}
        disabled={generating}
        style={{
          display: 'flex', alignItems: 'center', gap: 8,
          background: generating ? 'rgba(96,165,250,0.1)' : 'linear-gradient(135deg,#1d4ed8,#3b82f6)',
          border: generating ? '1px solid rgba(96,165,250,0.3)' : 'none',
          borderRadius: 8, color: '#fff',
          padding: '9px 18px', fontSize: 13, fontWeight: 600,
          cursor: generating ? 'not-allowed' : 'pointer',
          opacity: generating ? 0.7 : 1,
          transition: 'all 0.2s',
          boxShadow: generating ? 'none' : '0 4px 12px rgba(29,78,216,0.35)',
          whiteSpace: 'nowrap',
        }}
      >
        {generating
          ? <><span style={{ fontSize: 15 }}>⏳</span> Generating…</>
          : <><span style={{ fontSize: 15 }}>📄</span> Download Audit Report</>}
      </button>
      {error && (
        <div style={{ marginTop: 8, fontSize: 11, color: C.red }}>{error}</div>
      )}
    </div>
  );
}