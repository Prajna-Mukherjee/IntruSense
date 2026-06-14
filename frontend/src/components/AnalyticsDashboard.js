import React, { useState, useEffect, useCallback } from 'react';
import AuditReport from './AuditReport';
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  LineChart, Line, RadarChart, Radar, PolarGrid,
  PolarAngleAxis, PolarRadiusAxis,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  ResponsiveContainer
} from 'recharts';

const API_URL = 'http://localhost:8000';

// ── Palette ────────────────────────────────────────────────────────────────────
const C = {
  bg:       '#0a0e1a',
  card:     '#0f1829',
  border:   '#1e3a5f',
  accent:   '#60a5fa',
  red:      '#ef4444',
  orange:   '#f59e0b',
  green:    '#22c55e',
  purple:   '#a78bfa',
  cyan:     '#06b6d4',
  pink:     '#ec4899',
  indigo:   '#6366f1',
  text:     '#e2e8f0',
  muted:    '#64748b',
  subtle:   '#94a3b8',
};

const ATTACK_PALETTE = [
  C.red, C.orange, C.purple, C.cyan, C.pink, C.indigo, C.green, C.accent
];

// ── Tooltip shared style ───────────────────────────────────────────────────────
const TooltipBox = ({ active, payload, label, fmt }) => {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: '#0d1526', border: `1px solid ${C.border}`,
      borderRadius: 8, padding: '10px 14px', fontSize: 12
    }}>
      {label && <div style={{ color: C.subtle, marginBottom: 6, fontWeight: 600 }}>{label}</div>}
      {payload.map((p, i) => (
        <div key={i} style={{ color: p.color || C.text, marginBottom: 2 }}>
          {p.name}: <strong>{fmt ? fmt(p.value) : p.value}</strong>
        </div>
      ))}
    </div>
  );
};

// ── Card wrapper ───────────────────────────────────────────────────────────────
const Card = ({ title, icon, children, style = {}, titleRight }) => (
  <div style={{
    background: C.card, border: `1px solid ${C.border}`,
    borderRadius: 12, padding: '18px 20px', ...style
  }}>
    <div style={{
      display: 'flex', justifyContent: 'space-between',
      alignItems: 'center', marginBottom: 16
    }}>
      <div style={{ fontSize: 13, fontWeight: 700, color: C.accent, display: 'flex', alignItems: 'center', gap: 7 }}>
        <span>{icon}</span>{title}
      </div>
      {titleRight && <div>{titleRight}</div>}
    </div>
    {children}
  </div>
);

// ── Severity badge ─────────────────────────────────────────────────────────────
const severityColor = s => ({ Critical: C.red, High: C.orange, Medium: '#eab308', Low: C.green }[s] || C.muted);

// ─── ANALYTICS DASHBOARD ──────────────────────────────────────────────────────
export default function AnalyticsDashboard({ authHeaders = {}, externalAlerts = [] }) {
  const [logs,        setLogs]        = useState([]);
  const [stats,       setStats]       = useState({ total_logs: 0, total_threats: 0, attack_distribution: {}, detection_rate: 0 });
  const [loading,     setLoading]     = useState(true);
  const [timeRange,   setTimeRange]   = useState('24h');   // '1h' | '24h' | '7d' | '30d'

  // ── Fetch ────────────────────────────────────────────────────────────────────
  const fetchAll = useCallback(async () => {
    try {
      const [logsRes, statsRes] = await Promise.all([
        fetch(`${API_URL}/api/logs?size=500`, { headers: authHeaders }),
        fetch(`${API_URL}/api/stats`,         { headers: authHeaders }),
      ]);
      const logsData  = await logsRes.json();
      const statsData = await statsRes.json();
      setLogs(logsData.logs || []);
      setStats(statsData);
    } catch { /* backend not running — use externalAlerts */ }
    setLoading(false);
  }, [JSON.stringify(authHeaders)]);

  useEffect(() => { fetchAll(); const iv = setInterval(fetchAll, 15000); return () => clearInterval(iv); }, [fetchAll]);

  // Merge: prefer fetched logs; fall back to alerts passed from parent
  const allLogs = logs.length > 0 ? logs : externalAlerts;

  // ── Derived data ─────────────────────────────────────────────────────────────

  // 1. Attack distribution for Pie
  const attackDist = Object.entries(stats.attack_distribution || {})
    .filter(([k]) => k !== 'Benign')
    .sort((a, b) => b[1] - a[1])
    .map(([name, value], i) => ({ name, value, color: ATTACK_PALETTE[i % ATTACK_PALETTE.length] }));

  // 2. Timeline: bucket logs by time slot
  const timelineBuckets = buildTimeline(allLogs, timeRange);

  // 3. Threat score distribution histogram
  const scoreHist = buildScoreHistogram(allLogs);

  // 4. Top tactics bar
  const tacticsDist = buildTacticsDist(allLogs);

  // 5. Radar: attack category coverage
  const radarData = buildRadarData(stats.attack_distribution || {});

  // 6. Severity breakdown
  const severityData = buildSeverityData(allLogs);

  // 7. Recent top attackers table (by attack_type + count)
  const topAttacks = attackDist.slice(0, 5);

  if (loading) return (
    <div style={{ color: C.muted, textAlign: 'center', padding: '60px 0', fontSize: 14 }}>
      Loading analytics…
    </div>
  );

  if (allLogs.length === 0 && stats.total_logs === 0) return (
    <div style={{ textAlign: 'center', padding: '60px 0', color: C.muted }}>
      <div style={{ fontSize: 40, marginBottom: 12 }}>📊</div>
      <div style={{ fontSize: 14 }}>No data yet — upload logs or connect live traffic to see analytics.</div>
    </div>
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

      {/* ── Row 0: header with download ──────────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: -4 }}>
        <AuditReport authHeaders={authHeaders} />
      </div>

      {/* ── Row 1: KPI strip ─────────────────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
        <KPI icon="📊" label="Total Logs"       value={stats.total_logs}                     />
        <KPI icon="🚨" label="Threats"           value={stats.total_threats}   color={C.red}  />
        <KPI icon="🛡️" label="Benign"            value={stats.total_logs - stats.total_threats} color={C.green} />
        <KPI icon="📈" label="Detection Rate"    value={`${stats.detection_rate ?? 0}%`}     color={C.orange} />
        <KPI icon="🎯" label="Attack Types"      value={attackDist.length}                   color={C.purple} />
      </div>

      {/* ── Row 1: Timeline + Pie ────────────────────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 16 }}>

        <Card title="Threat Timeline" icon="📡"
          titleRight={
            <div style={{ display: 'flex', gap: 4 }}>
              {['1h','24h','7d','30d'].map(r => (
                <button key={r} onClick={() => setTimeRange(r)} style={{
                  background: timeRange === r ? C.accent : 'transparent',
                  border: `1px solid ${timeRange === r ? C.accent : C.border}`,
                  color: timeRange === r ? '#fff' : C.muted,
                  borderRadius: 5, padding: '2px 8px', fontSize: 11, cursor: 'pointer'
                }}>{r}</button>
              ))}
            </div>
          }
        >
          <ResponsiveContainer width="100%" height={220}>
            <AreaChart data={timelineBuckets} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="gthreat" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor={C.red}    stopOpacity={0.3} />
                  <stop offset="95%" stopColor={C.red}    stopOpacity={0}   />
                </linearGradient>
                <linearGradient id="gbenign" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor={C.accent} stopOpacity={0.2} />
                  <stop offset="95%" stopColor={C.accent} stopOpacity={0}   />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1a2640" />
              <XAxis dataKey="label" stroke={C.muted} fontSize={10} />
              <YAxis stroke={C.muted} fontSize={10} allowDecimals={false} />
              <Tooltip content={<TooltipBox />} />
              <Legend wrapperStyle={{ fontSize: 11, color: C.subtle }} />
              <Area type="monotone" dataKey="threats" name="Threats" stroke={C.red}    fill="url(#gthreat)" strokeWidth={2} dot={false} />
              <Area type="monotone" dataKey="benign"  name="Benign"  stroke={C.accent} fill="url(#gbenign)" strokeWidth={2} dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </Card>

        <Card title="Attack Distribution" icon="🥧">
          {attackDist.length === 0
            ? <div style={{ color: C.muted, textAlign: 'center', paddingTop: 60 }}>No threats recorded</div>
            : <>
                <ResponsiveContainer width="100%" height={160}>
                  <PieChart>
                    <Pie data={attackDist} cx="50%" cy="50%" innerRadius={45} outerRadius={72}
                      dataKey="value" paddingAngle={2} strokeWidth={0}>
                      {attackDist.map((e, i) => <Cell key={i} fill={e.color} />)}
                    </Pie>
                    <Tooltip formatter={(v, n) => [v, n]} contentStyle={{
                      background: '#0d1526', border: `1px solid ${C.border}`, borderRadius: 8, fontSize: 12
                    }} />
                  </PieChart>
                </ResponsiveContainer>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 4 }}>
                  {attackDist.slice(0, 5).map((d, i) => (
                    <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11 }}>
                      <span style={{ width: 8, height: 8, borderRadius: '50%', background: d.color, flexShrink: 0 }} />
                      <span style={{ flex: 1, color: C.subtle, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.name}</span>
                      <span style={{ color: C.text, fontWeight: 700 }}>{d.value}</span>
                    </div>
                  ))}
                </div>
              </>
          }
        </Card>
      </div>

      {/* ── Row 2: Score Histogram + Tactics bar ────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>

        <Card title="Threat Score Distribution" icon="🎚️">
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={scoreHist} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1a2640" />
              <XAxis dataKey="range" stroke={C.muted} fontSize={10} />
              <YAxis stroke={C.muted} fontSize={10} allowDecimals={false} />
              <Tooltip content={<TooltipBox />} />
              <Bar dataKey="count" name="Logs" radius={[4, 4, 0, 0]}>
                {scoreHist.map((e, i) => (
                  <Cell key={i} fill={e.score < 0.4 ? C.green : e.score < 0.7 ? C.orange : C.red} fillOpacity={0.85} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          <div style={{ display: 'flex', gap: 14, marginTop: 8, fontSize: 11, color: C.muted }}>
            <span><span style={{ color: C.green }}>■</span> Low (0–40%)</span>
            <span><span style={{ color: C.orange }}>■</span> Medium (40–70%)</span>
            <span><span style={{ color: C.red }}>■</span> High (70–100%)</span>
          </div>
        </Card>

        <Card title="MITRE Tactics Observed" icon="🗺️">
          {tacticsDist.length === 0
            ? <div style={{ color: C.muted, textAlign: 'center', paddingTop: 60 }}>No MITRE data yet</div>
            : <ResponsiveContainer width="100%" height={200}>
                <BarChart data={tacticsDist} layout="vertical" margin={{ top: 0, right: 16, left: 8, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1a2640" />
                  <XAxis type="number" stroke={C.muted} fontSize={10} allowDecimals={false} />
                  <YAxis type="category" dataKey="tactic" stroke={C.muted} fontSize={10} width={130} />
                  <Tooltip content={<TooltipBox />} />
                  <Bar dataKey="count" name="Events" radius={[0, 4, 4, 0]} fill={C.purple} fillOpacity={0.85} />
                </BarChart>
              </ResponsiveContainer>
          }
        </Card>
      </div>

      {/* ── Row 3: Radar + Severity + Top Attacks ───────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 16 }}>

        <Card title="Attack Category Radar" icon="📻">
          {radarData.length < 3
            ? <div style={{ color: C.muted, textAlign: 'center', paddingTop: 60, fontSize: 12 }}>Need 3+ categories</div>
            : <ResponsiveContainer width="100%" height={220}>
                <RadarChart cx="50%" cy="50%" outerRadius={75} data={radarData}>
                  <PolarGrid stroke={C.border} />
                  <PolarAngleAxis dataKey="category" tick={{ fill: C.muted, fontSize: 10 }} />
                  <PolarRadiusAxis stroke="none" tick={false} />
                  <Radar name="Events" dataKey="value" stroke={C.cyan} fill={C.cyan} fillOpacity={0.2} strokeWidth={2} />
                  <Tooltip content={<TooltipBox />} />
                </RadarChart>
              </ResponsiveContainer>
          }
        </Card>

        <Card title="Severity Breakdown" icon="⚠️">
          {severityData.every(d => d.value === 0)
            ? <div style={{ color: C.muted, textAlign: 'center', paddingTop: 60, fontSize: 12 }}>No threats yet</div>
            : <>
                <ResponsiveContainer width="100%" height={150}>
                  <PieChart>
                    <Pie data={severityData.filter(d => d.value > 0)}
                      cx="50%" cy="50%" outerRadius={60} dataKey="value" paddingAngle={3} strokeWidth={0}>
                      {severityData.map((e, i) => <Cell key={i} fill={e.color} />)}
                    </Pie>
                    <Tooltip contentStyle={{ background: '#0d1526', border: `1px solid ${C.border}`, borderRadius: 8, fontSize: 12 }} />
                  </PieChart>
                </ResponsiveContainer>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 4 }}>
                  {severityData.filter(d => d.value > 0).map((d, i) => (
                    <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ width: 8, height: 8, borderRadius: 2, background: d.color, flexShrink: 0 }} />
                      <span style={{ flex: 1, fontSize: 11, color: C.subtle }}>{d.name}</span>
                      <span style={{
                        background: `${d.color}22`, border: `1px solid ${d.color}44`,
                        borderRadius: 10, padding: '1px 8px', fontSize: 11, color: d.color, fontWeight: 700
                      }}>{d.value}</span>
                    </div>
                  ))}
                </div>
              </>
          }
        </Card>

        <Card title="Top Threat Types" icon="🏆">
          {topAttacks.length === 0
            ? <div style={{ color: C.muted, textAlign: 'center', paddingTop: 60, fontSize: 12 }}>No threats yet</div>
            : <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {topAttacks.map((a, i) => {
                  const pct = topAttacks[0].value > 0 ? (a.value / topAttacks[0].value) * 100 : 0;
                  return (
                    <div key={i}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, fontSize: 12 }}>
                        <span style={{ color: C.text }}>{a.name}</span>
                        <span style={{ color: a.color, fontWeight: 700 }}>{a.value}</span>
                      </div>
                      <div style={{ background: '#1a2640', borderRadius: 4, height: 5, overflow: 'hidden' }}>
                        <div style={{
                          width: `${pct}%`, height: '100%',
                          background: `linear-gradient(90deg, ${a.color}aa, ${a.color})`,
                          borderRadius: 4, transition: 'width 0.6s ease'
                        }} />
                      </div>
                    </div>
                  );
                })}
              </div>
          }
        </Card>
      </div>

      {/* ── Row 4: Activity heatmap (24h × weekday) ─────────────────────────── */}
      <Card title="Activity Heatmap — Threats by Hour × Day" icon="🔥">
        <ActivityHeatmap logs={allLogs} />
      </Card>

      {/* ── Row 5: Cumulative threat trend ──────────────────────────────────── */}
      <Card title="Cumulative Threats Over Time" icon="📈">
        <CumulativeTrendChart logs={allLogs} />
      </Card>

    </div>
  );
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function KPI({ icon, label, value, color = C.text }) {
  return (
    <div style={{
      background: C.card, border: `1px solid ${C.border}`, borderRadius: 10,
      padding: '14px 16px', display: 'flex', alignItems: 'center', gap: 12
    }}>
      <span style={{ fontSize: 24 }}>{icon}</span>
      <div>
        <div style={{ fontSize: 22, fontWeight: 800, color }}>{value}</div>
        <div style={{ fontSize: 11, color: C.muted, marginTop: 1 }}>{label}</div>
      </div>
    </div>
  );
}

// 24-col heatmap: hours (x) × days of week (y)
function ActivityHeatmap({ logs }) {
  const DAYS  = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const HOURS = Array.from({ length: 24 }, (_, i) => i);

  // Build counts[day][hour]
  const counts = Array.from({ length: 7 }, () => Array(24).fill(0));
  logs.filter(l => l.is_threat).forEach(l => {
    const d = new Date(l.timestamp);
    if (!isNaN(d)) counts[d.getDay()][d.getHours()]++;
  });
  const maxVal = Math.max(1, ...counts.flat());

  const cellW = 24, cellH = 22, paddingL = 32;

  return (
    <div style={{ overflowX: 'auto' }}>
      <svg width={paddingL + cellW * 24 + 10} height={cellH * 7 + 28}>
        {/* Hour labels */}
        {HOURS.map(h => (
          <text key={h} x={paddingL + h * cellW + cellW / 2} y={14}
            textAnchor="middle" fill={C.muted} fontSize={9}>{h}</text>
        ))}
        {/* Day rows */}
        {DAYS.map((day, di) => (
          <g key={di}>
            <text x={paddingL - 4} y={20 + di * cellH + cellH / 2 + 4}
              textAnchor="end" fill={C.muted} fontSize={10}>{day}</text>
            {HOURS.map(h => {
              const v   = counts[di][h];
              const pct = v / maxVal;
              const bg  = pct === 0
                ? '#111827'
                : pct < 0.3  ? '#7f1d1d'
                : pct < 0.6  ? '#b91c1c'
                : '#ef4444';
              return (
                <g key={h}>
                  <rect
                    x={paddingL + h * cellW + 1} y={20 + di * cellH + 1}
                    width={cellW - 2} height={cellH - 2}
                    rx={3} fill={bg} opacity={pct === 0 ? 0.4 : 0.85}
                  />
                  {v > 0 && (
                    <text x={paddingL + h * cellW + cellW / 2} y={20 + di * cellH + cellH / 2 + 4}
                      textAnchor="middle" fill="#fff" fontSize={8} fontWeight={700}>{v}</text>
                  )}
                </g>
              );
            })}
          </g>
        ))}
      </svg>
      <div style={{ fontSize: 11, color: C.muted, marginTop: 4 }}>
        Darker red = more threats in that hour slot. Only logs with timestamps are plotted.
      </div>
    </div>
  );
}

// Cumulative threat count line chart
function CumulativeTrendChart({ logs }) {
  const threats = logs
    .filter(l => l.is_threat && l.timestamp)
    .map(l => ({ ts: new Date(l.timestamp).getTime() }))
    .sort((a, b) => a.ts - b.ts);

  if (threats.length < 2) return (
    <div style={{ color: C.muted, textAlign: 'center', padding: '30px 0', fontSize: 12 }}>
      Need at least 2 threat events to draw trend.
    </div>
  );

  let cumul = 0;
  const data = threats.map(t => {
    cumul++;
    const d = new Date(t.ts);
    return {
      label: `${d.getMonth()+1}/${d.getDate()} ${String(d.getHours()).padStart(2,'0')}:${String(d.getMinutes()).padStart(2,'0')}`,
      threats: cumul
    };
  });

  // Downsample if too many points
  const sampled = data.length > 80 ? data.filter((_, i) => i % Math.ceil(data.length / 80) === 0) : data;

  return (
    <ResponsiveContainer width="100%" height={180}>
      <LineChart data={sampled} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1a2640" />
        <XAxis dataKey="label" stroke={C.muted} fontSize={9} interval="preserveStartEnd" />
        <YAxis stroke={C.muted} fontSize={10} allowDecimals={false} />
        <Tooltip content={<TooltipBox />} />
        <Line type="monotone" dataKey="threats" name="Cumulative Threats"
          stroke={C.red} strokeWidth={2} dot={false}
          style={{ filter: `drop-shadow(0 0 4px ${C.red})` }} />
      </LineChart>
    </ResponsiveContainer>
  );
}

// ── Data helpers ───────────────────────────────────────────────────────────────

function buildTimeline(logs, range) {
  const now   = Date.now();
  const msMap = { '1h': 3600000, '24h': 86400000, '7d': 604800000, '30d': 2592000000 };
  const bucketCount = { '1h': 12, '24h': 24, '7d': 7, '30d': 30 };
  const ms    = msMap[range] || msMap['24h'];
  const n     = bucketCount[range] || 24;
  const step  = ms / n;

  const buckets = Array.from({ length: n }, (_, i) => {
    const t = new Date(now - ms + i * step);
    const label = range === '1h' || range === '24h'
      ? `${String(t.getHours()).padStart(2,'0')}:${String(t.getMinutes()).padStart(2,'0')}`
      : `${t.getMonth()+1}/${t.getDate()}`;
    return { label, threats: 0, benign: 0, _start: now - ms + i * step };
  });

  logs.forEach(l => {
    const ts = new Date(l.timestamp).getTime();
    if (isNaN(ts) || ts < now - ms) return;
    const idx = Math.min(n - 1, Math.floor((ts - (now - ms)) / step));
    if (l.is_threat) buckets[idx].threats++;
    else             buckets[idx].benign++;
  });

  return buckets;
}

function buildScoreHistogram(logs) {
  const bands = [
    { range: '0–10%',  score: 0.05, count: 0 }, { range: '10–20%', score: 0.15, count: 0 },
    { range: '20–30%', score: 0.25, count: 0 }, { range: '30–40%', score: 0.35, count: 0 },
    { range: '40–50%', score: 0.45, count: 0 }, { range: '50–60%', score: 0.55, count: 0 },
    { range: '60–70%', score: 0.65, count: 0 }, { range: '70–80%', score: 0.75, count: 0 },
    { range: '80–90%', score: 0.85, count: 0 }, { range: '90–100%',score: 0.95, count: 0 },
  ];
  logs.forEach(l => {
    const s = l.threat_score ?? 0;
    const i = Math.min(9, Math.floor(s * 10));
    bands[i].count++;
  });
  return bands;
}

function buildTacticsDist(logs) {
  const counts = {};
  logs.forEach(l => {
    const t = l.mitre?.tactic || l.mitre_tactic;
    if (t && t !== 'unknown') {
      const label = t.replace(/-/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
      counts[label] = (counts[label] || 0) + 1;
    }
  });
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([tactic, count]) => ({ tactic, count }));
}

function buildRadarData(dist) {
  const CATEGORIES = {
    'DoS':                'DoS / DDoS',
    'DDoS':               'DoS / DDoS',
    'PortScan':           'Recon',
    'BruteForce':         'Credential',
    'Exploit':            'Exploit',
    'C2':                 'C2',
    'LateralMovement':    'Lateral',
    'Exfiltration':       'Exfiltration',
    'WebAttack':          'Web Attack',
    'Anomalous Behavior': 'Anomaly',
  };
  const merged = {};
  Object.entries(dist).forEach(([k, v]) => {
    const cat = CATEGORIES[k] || k;
    merged[cat] = (merged[cat] || 0) + v;
  });
  return Object.entries(merged).map(([category, value]) => ({ category, value }));
}

function buildSeverityData(logs) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  logs.forEach(l => {
    const s = l.mitre?.severity;
    if (s && counts[s] !== undefined) counts[s]++;
    else if (l.is_threat) {
      if      ((l.threat_score || 0) > 0.85) counts.Critical++;
      else if ((l.threat_score || 0) > 0.7)  counts.High++;
      else if ((l.threat_score || 0) > 0.4)  counts.Medium++;
      else                                    counts.Low++;
    }
  });
  return [
    { name: 'Critical', value: counts.Critical, color: C.red    },
    { name: 'High',     value: counts.High,     color: C.orange },
    { name: 'Medium',   value: counts.Medium,   color: '#eab308' },
    { name: 'Low',      value: counts.Low,       color: C.green  },
  ];
}