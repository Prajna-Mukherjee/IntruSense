import React, { useState, useEffect, useCallback } from 'react';

const API_URL = 'http://localhost:8000';

const threatBadge = (is_threat, score) => ({
  background: is_threat ? (score > 0.7 ? '#ef4444' : '#f59e0b') : '#22c55e',
  color: '#fff', padding: '2px 8px', borderRadius: '20px',
  fontSize: '10px', fontWeight: 700
});

export default function LiveFeed({ apiUrl = API_URL, authHeaders = {}, refreshKey = 0 }) {
  const [logs, setLogs]         = useState([]);
  const [loading, setLoading]   = useState(true);
  const [deleting, setDeleting] = useState(null);
  const [clearing, setClearing] = useState(false);
  const [confirm, setConfirm]   = useState(false);

  const fetchLogs = useCallback(async () => {
    try {
      const res  = await fetch(`${apiUrl}/api/logs?size=20`, { headers: authHeaders });
      const data = await res.json();
      setLogs(data.logs || []);
    } catch {}
    setLoading(false);
  }, [apiUrl, JSON.stringify(authHeaders)]);

  useEffect(() => {
    fetchLogs();
    const interval = setInterval(fetchLogs, 5000);
    return () => clearInterval(interval);
  }, [fetchLogs, refreshKey]);

  const handleDeleteRow = async (log) => {
    const id    = log.log_id;
    const es_id = log._es_id || "";
    setDeleting(id);
    try {
      const url = `${apiUrl}/api/logs/${id}${es_id ? `?es_id=${encodeURIComponent(es_id)}` : ''}`;
      const res = await fetch(url, { method: 'DELETE', headers: authHeaders });
      if (res.ok) {
        // Remove from local state immediately — poll will confirm on next tick
        setLogs(prev => prev.filter(l => l.log_id !== id));
      }
    } catch {}
    setDeleting(null);
  };

  const handleClearAll = async () => {
    setClearing(true);
    setConfirm(false);
    try {
      const res = await fetch(`${apiUrl}/api/logs`, { method: 'DELETE', headers: authHeaders });
      if (res.ok) setLogs([]);
    } catch {}
    setClearing(false);
  };

  if (loading) return (
    <div style={{ color: '#475569', padding: '20px', textAlign: 'center' }}>Loading logs...</div>
  );
  if (logs.length === 0) return (
    <div style={{ color: '#475569', padding: '20px', textAlign: 'center' }}>
      No logs yet. Upload a file to get started.
    </div>
  );

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 10, gap: 8 }}>
        {confirm ? (
          <>
            <span style={{ fontSize: 12, color: '#94a3b8', alignSelf: 'center' }}>
              Delete all {logs.length} logs permanently?
            </span>
            <button onClick={handleClearAll} disabled={clearing} style={btnStyle('#ef4444')}>
              {clearing ? 'Clearing…' : 'Yes, delete all'}
            </button>
            <button onClick={() => setConfirm(false)} style={btnStyle('#475569')}>Cancel</button>
          </>
        ) : (
          <button onClick={() => setConfirm(true)} style={btnStyle('#ef4444')}>🗑️ Clear All Logs</button>
        )}
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid #1e3a5f' }}>
              {['Time','Status','Attack Type','Threat Score','Confidence','MITRE ID','Tactic',''].map(h => (
                <th key={h} style={{ textAlign:'left', padding:'8px 12px', color:'#64748b', fontWeight:600 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {logs.map((log, i) => {
              const isDel = deleting === log.log_id;
              return (
                <tr key={log.log_id || i}
                  style={{ borderBottom:'1px solid #0d1526', transition:'background 0.15s', opacity: isDel ? 0.4 : 1 }}
                  onMouseEnter={e => e.currentTarget.style.background = 'rgba(30,58,95,0.3)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                  <td style={{ padding:'8px 12px', color:'#64748b' }}>
                    {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : '--'}
                  </td>
                  <td style={{ padding:'8px 12px' }}>
                    <span style={threatBadge(log.is_threat, log.threat_score)}>
                      {log.is_threat ? 'THREAT' : 'CLEAN'}
                    </span>
                  </td>
                  <td style={{ padding:'8px 12px', color: log.is_threat ? '#f87171' : '#94a3b8' }}>
                    {log.attack_type || 'Benign'}
                  </td>
                  <td style={{ padding:'8px 12px', color:'#e2e8f0' }}>
                    {log.threat_score !== undefined ? `${Math.round(log.threat_score * 100)}%` : '--'}
                  </td>
                  <td style={{ padding:'8px 12px', color:'#94a3b8' }}>
                    {log.confidence !== undefined ? `${Math.round(log.confidence * 100)}%` : '--'}
                  </td>
                  <td style={{ padding:'8px 12px', color:'#60a5fa', fontFamily:'monospace' }}>
                    {log.mitre?.technique_id || log.mitre_technique_id || '--'}
                  </td>
                  <td style={{ padding:'8px 12px', color:'#94a3b8' }}>
                    {log.mitre?.tactic || log.mitre_tactic || '--'}
                  </td>
                  <td style={{ padding:'8px 12px' }}>
                    <button
                      onClick={() => handleDeleteRow(log)}
                      disabled={isDel}
                      title="Delete this log"
                      style={{
                        background:'none', border:'1px solid rgba(239,68,68,0.3)',
                        borderRadius:6, color:'#ef4444',
                        cursor: isDel ? 'not-allowed' : 'pointer',
                        padding:'3px 8px', fontSize:12, opacity: isDel ? 0.5 : 1,
                      }}
                      onMouseEnter={e => { if (!isDel) e.currentTarget.style.background='rgba(239,68,68,0.12)'; }}
                      onMouseLeave={e => { e.currentTarget.style.background='none'; }}
                    >
                      {isDel ? '…' : '🗑️'}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function btnStyle(color) {
  return {
    background: `rgba(${color === '#ef4444' ? '239,68,68' : '71,85,105'},0.12)`,
    border: `1px solid ${color}55`, borderRadius:7, color,
    padding:'5px 12px', fontSize:12, fontWeight:600, cursor:'pointer',
  };
}