import React, { useState } from 'react';

const SEVERITY_COLOR = {
  Critical: '#ef4444',
  High:     '#f97316',
  Medium:   '#f59e0b',
  Low:      '#22c55e',
  None:     '#22c55e',
};

const TACTIC_ICON = {
  'initial-access':       '🚪',
  'execution':            '⚙️',
  'persistence':          '📌',
  'privilege-escalation': '⬆️',
  'defense-evasion':      '🕵️',
  'credential-access':    '🔑',
  'discovery':            '🔎',
  'lateral-movement':     '↔️',
  'collection':           '📦',
  'command-and-control':  '📡',
  'exfiltration':         '📤',
  'impact':               '💥',
  'resource-development': '🏗️',
  'reconnaissance':       '🧭',
};

export default function MITREPanel({ mitre }) {
  const [showDetails, setShowDetails] = useState(false);

  if (!mitre || !mitre.technique_id) {
    return (
      <div style={{ color: '#475569', textAlign: 'center', padding: '20px' }}>
        No MITRE data available
      </div>
    );
  }

  const color       = SEVERITY_COLOR[mitre.severity] || '#64748b';
  const tacticIcon  = TACTIC_ICON[mitre.tactic] || '⚠️';
  const tacticLabel = mitre.tactic_display || (mitre.tactic || '').replace(/-/g, ' ');
  const platforms   = mitre.platforms   || [];
  const dataSources = mitre.data_sources || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>

      {/* ── Header card ── */}
      <div style={{
        background: `${color}15`,
        border: `1px solid ${color}40`,
        borderRadius: '10px',
        padding: '14px'
      }}>
        <div style={{ fontSize: '22px', fontWeight: 800, color, marginBottom: '4px' }}>
          {mitre.technique_id}
        </div>
        <div style={{ fontSize: '14px', fontWeight: 600, color: '#e2e8f0', marginBottom: '10px' }}>
          {mitre.technique_name}
        </div>

        {/* Badges */}
        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
          <span style={{
            background: '#1e3a5f', borderRadius: '4px',
            padding: '2px 8px', fontSize: '11px', color: '#60a5fa'
          }}>
            {tacticIcon} {tacticLabel}
          </span>
          <span style={{
            background: `${color}25`, borderRadius: '4px',
            padding: '2px 8px', fontSize: '11px', color
          }}>
            {mitre.severity}
          </span>
        </div>
      </div>

      {/* ── Description ── */}
      <div style={{ fontSize: '12px', color: '#94a3b8', lineHeight: '1.6' }}>
        {mitre.description}
      </div>

      {/* ── Expandable details (platforms + data sources) ── */}
      {(platforms.length > 0 || dataSources.length > 0) && (
        <div>
          <button
            onClick={() => setShowDetails(v => !v)}
            style={{
              background: 'none', border: '1px solid #1e3a5f',
              borderRadius: '6px', padding: '4px 10px',
              fontSize: '11px', color: '#60a5fa',
              cursor: 'pointer', marginBottom: showDetails ? '8px' : '0'
            }}
          >
            {showDetails ? '▲ Hide details' : '▼ Show details'}
          </button>

          {showDetails && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>

              {/* Platforms */}
              {platforms.length > 0 && (
                <div>
                  <div style={{ fontSize: '11px', color: '#64748b', marginBottom: '4px', fontWeight: 600 }}>
                    PLATFORMS
                  </div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                    {platforms.map((p, i) => (
                      <span key={i} style={{
                        background: '#0f1829', border: '1px solid #1e3a5f',
                        borderRadius: '4px', padding: '2px 6px',
                        fontSize: '10px', color: '#94a3b8'
                      }}>
                        {p}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Data Sources */}
              {dataSources.length > 0 && (
                <div>
                  <div style={{ fontSize: '11px', color: '#64748b', marginBottom: '4px', fontWeight: 600 }}>
                    DATA SOURCES
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                    {dataSources.map((ds, i) => (
                      <div key={i} style={{ fontSize: '11px', color: '#94a3b8' }}>
                        · {ds}
                      </div>
                    ))}
                  </div>
                </div>
              )}

            </div>
          )}
        </div>
      )}

      {/* ── ATT&CK link ── */}
      {mitre.url && (
        <a
          href={mitre.url}
          target="_blank"
          rel="noreferrer"
          style={{
            fontSize: '12px', color: '#60a5fa',
            textDecoration: 'none',
            display: 'flex', alignItems: 'center', gap: '4px'
          }}
        >
          🔗 View on MITRE ATT&amp;CK
        </a>
      )}
    </div>
  );
}