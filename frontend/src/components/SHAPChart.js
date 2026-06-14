import React from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Cell, ResponsiveContainer } from 'recharts';

export default function SHAPChart({ shapData }) {
  if (!shapData || !shapData.top_features) {
    return <div style={{ color: '#475569', textAlign: 'center', padding: '30px' }}>No explanation available</div>;
  }

  const data = shapData.top_features.map(f => ({
    feature: f.feature.replace(/_/g, ' '),
    impact: f.impact,
    absImpact: Math.abs(f.impact)
  })).sort((a, b) => b.absImpact - a.absImpact).slice(0, 10);

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      const d = payload[0].payload;
      return (
        <div style={{ background: '#0f1829', border: '1px solid #1e3a5f', padding: '8px 12px', borderRadius: '8px', fontSize: '12px' }}>
          <div style={{ fontWeight: 600, color: '#e2e8f0', marginBottom: '4px' }}>{d.feature}</div>
          <div style={{ color: d.impact > 0 ? '#ef4444' : '#22c55e' }}>
            Impact: {d.impact > 0 ? '+' : ''}{d.impact.toFixed(4)}
          </div>
        </div>
      );
    }
    return null;
  };

  return (
    <div>
      <div style={{ fontSize: '12px', color: '#64748b', marginBottom: '10px' }}>
        🔴 Increases threat likelihood · 🟢 Decreases threat likelihood
      </div>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={data} layout="vertical" margin={{ left: 10, right: 30, top: 0, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e3a5f" />
          <XAxis type="number" stroke="#475569" fontSize={11} tickFormatter={v => v.toFixed(2)} />
          <YAxis type="category" dataKey="feature" stroke="#475569" fontSize={11} width={140} />
          <Tooltip content={<CustomTooltip />} />
          <Bar dataKey="impact" radius={[0, 4, 4, 0]}>
            {data.map((entry, i) => (
              <Cell key={i} fill={entry.impact > 0 ? '#ef4444' : '#22c55e'} fillOpacity={0.85} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
