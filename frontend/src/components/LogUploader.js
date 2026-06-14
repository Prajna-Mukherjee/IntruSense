import React, { useState } from 'react';

export default function LogUploader({ onResult, apiUrl, authHeaders = {} }) {
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [dragOver, setDragOver] = useState(false);

  const analyzeFile = async (file) => {
    if (!file || !file.name.endsWith('.csv')) {
      setMessage('❌ Please upload a CSV file');
      return;
    }
    setLoading(true);
    setMessage('🔄 Analyzing...');
    const form = new FormData();
    form.append('file', file);
    try {
      const res = await fetch(`${apiUrl}/api/analyze`, { method: 'POST', body: form, headers: authHeaders });
      const data = await res.json();
      setMessage(`✅ ${data.total} logs · ${data.threats_detected} threats found`);
      onResult(data);
    } catch {
      setMessage('❌ Analysis failed. Is the backend running?');
    }
    setLoading(false);
  };

  const onDrop = (e) => {
    e.preventDefault(); setDragOver(false);
    analyzeFile(e.dataTransfer.files[0]);
  };

  return (
    <div>
      <div
        onDrop={onDrop}
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onClick={() => document.getElementById('fileInput').click()}
        style={{
          border: `2px dashed ${dragOver ? '#60a5fa' : '#1e3a5f'}`,
          borderRadius: '10px', padding: '28px 16px',
          textAlign: 'center', cursor: 'pointer',
          background: dragOver ? 'rgba(96,165,250,0.08)' : 'transparent',
          transition: 'all 0.2s'
        }}
      >
        <div style={{ fontSize: '32px', marginBottom: '8px' }}>📁</div>
        <div style={{ fontSize: '13px', color: '#94a3b8' }}>Drop CSV log file here</div>
        <div style={{ fontSize: '11px', color: '#475569', marginTop: '4px' }}>or click to browse</div>
        <input id="fileInput" type="file" accept=".csv" style={{ display: 'none' }}
          onChange={(e) => analyzeFile(e.target.files[0])} />
      </div>

      {message && (
        <div style={{ marginTop: '10px', fontSize: '12px', color: '#94a3b8', textAlign: 'center', padding: '8px', background: '#0a0e1a', borderRadius: '6px' }}>
          {loading && <span style={{ marginRight: '6px' }}>⏳</span>}
          {message}
        </div>
      )}

      <div style={{ marginTop: '14px', fontSize: '11px', color: '#475569' }}>
        <strong style={{ color: '#64748b', display: 'block', marginBottom: '4px' }}>Expected CSV columns:</strong>
        flow_duration, flow_bytes_s, syn_flag_count, ...
      </div>
    </div>
  );
}
