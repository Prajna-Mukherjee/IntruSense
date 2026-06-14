import React from 'react';

const severityColor = (score, attackType) => {
  if (attackType && attackType !== 'Benign') {
    if (score > 0.7) return '#ef4444';
    return '#f59e0b';
  }
  if (score > 0.7) return '#ef4444';
  if (score > 0.4) return '#f59e0b';
  return '#22c55e';
};

// Updated for NSL-KDD attack taxonomy
const attackIcon = (type) => {
  const icons = {
    'DoS':                '🔥',
    'DDoS':               '💥',
    'PortScan':           '🔎',
    'BruteForce':         '🔐',
    'Exploit':            '💣',
    'C2':                 '📡',
    'LateralMovement':    '↔️',
    'Exfiltration':       '📤',
    'WebAttack':          '🌐',
    'Anomalous Behavior': '👾',
    'Benign':             '✅',
  };
  return icons[type] || '⚠️';
};

const attackLabel = (type) => {
  const labels = {
    'DoS':                'Denial of Service',
    'DDoS':               'Distributed DoS',
    'PortScan':           'Port Scan',
    'BruteForce':         'Brute Force',
    'Exploit':            'Exploitation (U2R)',
    'C2':                 'Command & Control',
    'LateralMovement':    'Lateral Movement',
    'Exfiltration':       'Data Exfiltration',
    'WebAttack':          'Web Attack',
    'Anomalous Behavior': 'Anomalous Behavior',
    'Benign':             'Benign',
  };
  return labels[type] || type;
};

export default function AlertPanel({ alerts, onSelect, selected }) {
  if (!alerts || alerts.length === 0) {
    return (
      <div style={{ textAlign: 'center', padding: '40px 0', color: '#475569' }}>
        <div style={{ fontSize: '40px', marginBottom: '12px' }}>🔍</div>
        <div>No threats detected yet. Upload a log file or connect live traffic.</div>
      </div>
    );
  }

  return (
    <div style={{ maxHeight: '280px', overflowY: 'auto' }}>
      {alerts.map((alert, i) => {
        const isSelected  = selected === alert;
        const scoreColor  = severityColor(alert.threat_score, alert.attack_type);
        const icon        = attackIcon(alert.attack_type);
        const label       = attackLabel(alert.attack_type);
        const techniqueId = alert.mitre?.technique_id || 'N/A';
        const tactic      = alert.mitre?.tactic_display || alert.mitre?.tactic || '';
        const time        = alert.timestamp
          ? new Date(alert.timestamp).toLocaleTimeString()
          : '';

        return (
          <div
            key={i}
            onClick={() => onSelect(alert)}
            style={{
              display: 'flex', alignItems: 'center', gap: '12px',
              padding: '10px 12px', borderRadius: '8px', cursor: 'pointer',
              marginBottom: '6px', border: '1px solid',
              borderColor: isSelected ? scoreColor : '#1e3a5f',
              background: isSelected ? 'rgba(30,58,95,0.5)' : 'rgba(15,24,41,0.5)',
              transition: 'all 0.15s'
            }}
          >
            <span style={{ fontSize: '20px' }}>{icon}</span>

            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontWeight: 600, fontSize: '13px', color: scoreColor }}>
                {label}
              </div>
              <div style={{ fontSize: '11px', color: '#64748b', marginTop: '2px' }}>
                {techniqueId}{tactic ? ` · ${tactic}` : ''} · {time}
              </div>
            </div>

            <div style={{
              background: scoreColor, color: '#fff',
              borderRadius: '20px', padding: '2px 8px',
              fontSize: '11px', fontWeight: 700, whiteSpace: 'nowrap'
            }}>
              {Math.round(alert.threat_score * 100)}%
            </div>
          </div>
        );
      })}
    </div>
  );
}