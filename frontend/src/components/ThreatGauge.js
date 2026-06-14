import React from 'react';

export default function ThreatGauge({ score, attackType }) {
  const pct = Math.round((score || 0) * 100);
  const color = pct > 70 ? '#ef4444' : pct > 40 ? '#f59e0b' : '#22c55e';
  const label = pct > 70 ? 'CRITICAL' : pct > 40 ? 'MEDIUM' : 'LOW';

  // SVG arc gauge
  const r = 60, cx = 80, cy = 80;
  const start = Math.PI * 0.75;
  const end = start + (Math.PI * 1.5) * (pct / 100);
  const x1 = cx + r * Math.cos(start), y1 = cy + r * Math.sin(start);
  const x2 = cx + r * Math.cos(end), y2 = cy + r * Math.sin(end);
  const largeArc = pct > 66 ? 1 : 0;

  return (
    <div style={{ textAlign: 'center' }}>
      <svg width="160" height="130" viewBox="0 0 160 130">
        {/* Background arc */}
        <path d={`M ${cx + r * Math.cos(start)} ${cy + r * Math.sin(start)} A ${r} ${r} 0 1 1 ${cx + r * Math.cos(start + Math.PI * 1.5)} ${cy + r * Math.sin(start + Math.PI * 1.5)}`}
          fill="none" stroke="#1e3a5f" strokeWidth="10" strokeLinecap="round" />
        {/* Value arc */}
        {pct > 0 && (
          <path d={`M ${x1} ${y1} A ${r} ${r} 0 ${largeArc} 1 ${x2} ${y2}`}
            fill="none" stroke={color} strokeWidth="10" strokeLinecap="round"
            style={{ filter: `drop-shadow(0 0 6px ${color})` }} />
        )}
        <text x={cx} y={cy + 8} textAnchor="middle" fill={color} fontSize="24" fontWeight="800">{pct}%</text>
        <text x={cx} y={cy + 26} textAnchor="middle" fill="#64748b" fontSize="10">{label}</text>
      </svg>
      <div style={{ fontSize: '12px', color: '#94a3b8', marginTop: '4px' }}>{attackType}</div>
    </div>
  );
}
