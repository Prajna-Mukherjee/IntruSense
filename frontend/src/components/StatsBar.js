import React from 'react';

const StatCard = ({ icon, label, value, color }) => (
  <div style={{
    background: '#0f1829', border: '1px solid #1e3a5f', borderRadius: '10px',
    padding: '16px 20px', flex: 1, display: 'flex', alignItems: 'center', gap: '14px'
  }}>
    <span style={{ fontSize: '28px' }}>{icon}</span>
    <div>
      <div style={{ fontSize: '24px', fontWeight: 800, color: color || '#e2e8f0' }}>{value}</div>
      <div style={{ fontSize: '12px', color: '#64748b', marginTop: '2px' }}>{label}</div>
    </div>
  </div>
);

export default function StatsBar({ stats }) {
  return (
    <div style={{ display: 'flex', gap: '12px' }}>
      <StatCard icon="📊" label="Total Logs" value={stats.total_logs || 0} />
      <StatCard icon="🚨" label="Threats Detected" value={stats.total_threats || 0} color="#ef4444" />
      <StatCard icon="📈" label="Detection Rate" value={`${stats.detection_rate || 0}%`} color="#f59e0b" />
      <StatCard icon="🏆" label="Top Attack" value={
        Object.entries(stats.attack_distribution || {})
          .filter(([k]) => k !== 'Benign')
          .sort((a, b) => b[1] - a[1])[0]?.[0] || 'None'
      } color="#60a5fa" />
    </div>
  );
}
