import React, { useState, useEffect, useCallback } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useNavigate, useSearchParams } from 'react-router-dom';
import AlertPanel         from './components/AlertPanel';
import SHAPChart          from './components/SHAPChart';
import MITREPanel         from './components/MITREPanel';
import ThreatGauge        from './components/ThreatGauge';
import StatsBar           from './components/StatsBar';
import LogUploader        from './components/LogUploader';
import LiveFeed           from './components/LiveFeed';
import AnalyticsDashboard from './components/AnalyticsDashboard';
import Login              from './components/Login';
import Register           from './components/Register';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';
const WS_URL  = (process.env.REACT_APP_API_URL || 'http://localhost:8000')
                  .replace(/^http/, 'ws') + '/ws';

const styles = {
  app:    { minHeight: '100vh', background: '#0a0e1a', color: '#e2e8f0' },
  header: {
    background: 'linear-gradient(135deg, #1e3a5f 0%, #0d1b2e 100%)',
    borderBottom: '1px solid #1e3a5f',
    padding: '16px 24px',
    display: 'flex', alignItems: 'center', justifyContent: 'space-between'
  },
  logo:      { display: 'flex', alignItems: 'center', gap: '12px' },
  logoIcon:  { fontSize: '28px' },
  title:     { fontSize: '20px', fontWeight: 700, color: '#60a5fa', letterSpacing: '0.5px' },
  subtitle:  { fontSize: '12px', color: '#64748b', marginTop: '2px' },
  statusDot: (connected) => ({
    width: 10, height: 10, borderRadius: '50%',
    background: connected ? '#22c55e' : '#ef4444',
    display: 'inline-block', marginRight: 6,
    boxShadow: connected ? '0 0 8px #22c55e' : '0 0 8px #ef4444'
  }),
  statusText: { fontSize: '13px', color: '#94a3b8' },
  main:       { padding: '20px 24px', maxWidth: '1600px', margin: '0 auto' },
  grid:       { display: 'grid', gap: '16px' },
  row:        { display: 'grid', gap: '16px' },
  card:       { background: '#0f1829', border: '1px solid #1e3a5f', borderRadius: '12px', padding: '20px' },
  cardTitle:  {
    fontSize: '14px', fontWeight: 600, color: '#60a5fa',
    marginBottom: '14px', display: 'flex', alignItems: 'center', gap: '8px'
  },
};

const TABS = [
  { id: 'overview',  label: '🛡️  Overview'  },
  { id: 'analytics', label: '📊  Analytics' },
];

function TabBar({ active, onChange }) {
  return (
    <div style={{
      display: 'flex', gap: 4,
      background: 'rgba(15,24,41,0.7)',
      border: '1px solid #1e3a5f',
      borderRadius: 10, padding: 4,
    }}>
      {TABS.map(t => (
        <button key={t.id} onClick={() => onChange(t.id)} style={{
          background:   active === t.id ? '#1e3a5f' : 'transparent',
          border:       active === t.id ? '1px solid #3b5f8a' : '1px solid transparent',
          borderRadius: 7,
          color:        active === t.id ? '#60a5fa' : '#64748b',
          padding:      '6px 18px',
          fontSize:     13,
          fontWeight:   active === t.id ? 700 : 500,
          cursor:       'pointer',
          transition:   'all 0.15s',
          whiteSpace:   'nowrap',
        }}>{t.label}</button>
      ))}
    </div>
  );
}

// ── OAuth Callback Page ───────────────────────────────────────────────────────
function OAuthCallback() {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();

  useEffect(() => {
    const code = searchParams.get('code');
    if (!code) {
      navigate('/login');
      return;
    }
    setSearchParams({}, { replace: true });
    fetch(`${API_URL}/auth/exchange?code=${encodeURIComponent(code)}`)
      .then(res => {
        if (!res.ok) throw new Error('Exchange failed');
        return res.json();
      })
      .then(data => {
        sessionStorage.setItem('intrusense_auth', data.token);
        sessionStorage.setItem('intrusense_name', data.name);
        navigate('/dashboard', { replace: true });
      })
      .catch(() => navigate('/login'));
  }, []);

  return (
    <div style={{
      minHeight: '100vh', display: 'flex',
      alignItems: 'center', justifyContent: 'center',
      background: '#050a14', color: '#00d4ff',
      fontFamily: "'Orbitron', sans-serif", fontSize: 14, letterSpacing: 2
    }}>
      AUTHENTICATING...
    </div>
  );
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
function Dashboard() {
  const [wsConnected,   setWsConnected]   = useState(false);
  const [alerts,        setAlerts]        = useState([]);
  const [allResults,    setAllResults]    = useState([]);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [activeTab,     setActiveTab]     = useState('overview');
  const [refreshKey,    setRefreshKey]    = useState(0);
  const [stats,         setStats]         = useState({
    total_logs: 0, total_threats: 0, attack_distribution: {}, detection_rate: 0
  });

  const navigate = useNavigate();

  const authHeaders = useCallback(() => {
    const token = sessionStorage.getItem('intrusense_auth');
    return token ? { Authorization: `Bearer ${token}` } : {};
  }, []);

  const handleLogout = () => {
    sessionStorage.removeItem('intrusense_auth');
    sessionStorage.removeItem('intrusense_name');
    navigate('/login');
  };

  const fetchStats = useCallback(async () => {
    try {
      const res  = await fetch(`${API_URL}/api/stats`, { headers: authHeaders() });
      const data = await res.json();
      setStats(data);
    } catch {}
  }, [authHeaders]);

  const connectWS = useCallback(() => {
    const token = sessionStorage.getItem('intrusense_auth');
    if (!token) return;

    const socket = new WebSocket(`${WS_URL}?token=${encodeURIComponent(token)}`);

    socket.onopen    = () => { setWsConnected(true); };
    socket.onclose   = (e) => {
      setWsConnected(false);
      if (e.code === 4001) {
        navigate('/login');
        return;
      }
      setTimeout(connectWS, 3000);
    };
    socket.onerror   = () => { setWsConnected(false); };
    socket.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === 'THREAT_ALERT') {
          setAlerts(prev => [msg.data, ...prev].slice(0, 100));
          fetchStats();
        }
      } catch {}
    };
  }, [navigate, fetchStats]);

  useEffect(() => {
    connectWS();
    fetchStats();
    const iv = setInterval(fetchStats, 10000);
    return () => clearInterval(iv);
  }, [connectWS, fetchStats]);

  const handleAnalysisResult = (results) => {
    if (results?.results) {
      const all     = results.results;
      const threats = all.filter(r => r.is_threat);
      setAlerts(prev => [...threats, ...prev].slice(0, 100));
      setAllResults(prev => [...all, ...prev].slice(0, 500));
      if (threats.length > 0) setSelectedAlert(threats[0]);
      setTimeout(() => {
        fetchStats();
        setRefreshKey(k => k + 1);
      }, 1500);
    }
  };

  const headers = authHeaders();

  return (
    <div style={styles.app}>
      <header style={styles.header}>
        <div style={styles.logo}>
          <span style={styles.logoIcon}>🛡️</span>
          <div>
            <div style={styles.title}>IntruSense : An AI Threat Detection Platform</div>
            <div style={styles.subtitle}>Explainable AI · MITRE ATT&amp;CK · Real-time Alerts</div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
          <TabBar active={activeTab} onChange={setActiveTab} />
          <div>
            <span style={styles.statusDot(wsConnected)} />
            <span style={styles.statusText}>{wsConnected ? 'Live' : 'Connecting…'}</span>
          </div>
          <button
            onClick={handleLogout}
            style={{
              background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)',
              borderRadius: '8px', color: '#f87171', padding: '7px 16px',
              fontSize: '13px', fontWeight: 600, cursor: 'pointer',
              display: 'flex', alignItems: 'center', gap: '6px', transition: 'all 0.2s',
            }}
            onMouseEnter={e => {
              e.currentTarget.style.background  = 'rgba(239,68,68,0.2)';
              e.currentTarget.style.borderColor = 'rgba(239,68,68,0.6)';
            }}
            onMouseLeave={e => {
              e.currentTarget.style.background  = 'rgba(239,68,68,0.1)';
              e.currentTarget.style.borderColor = 'rgba(239,68,68,0.3)';
            }}
          >
            <span>🚪</span> Logout
          </button>
        </div>
      </header>

      <main style={styles.main}>
        {activeTab === 'overview' && (
          <div style={styles.grid}>
            <StatsBar stats={stats} />

            <div style={{ ...styles.row, gridTemplateColumns: '340px 1fr' }}>
              <div style={styles.card}>
                <div style={styles.cardTitle}><span>📤</span> Upload Logs</div>
                <LogUploader onResult={handleAnalysisResult} apiUrl={API_URL} authHeaders={headers} />
              </div>
              <div style={styles.card}>
                <div style={styles.cardTitle}><span>🚨</span> Threat Alerts</div>
                <AlertPanel alerts={alerts} onSelect={setSelectedAlert} selected={selectedAlert} />
              </div>
            </div>

            {selectedAlert && (
              <div style={{ ...styles.row, gridTemplateColumns: '200px 1fr 320px' }}>
                <div style={styles.card}>
                  <div style={styles.cardTitle}><span>⚡</span> Threat Score</div>
                  <ThreatGauge score={selectedAlert.threat_score} attackType={selectedAlert.attack_type} />
                </div>
                <div style={styles.card}>
                  <div style={styles.cardTitle}><span>🔍</span> SHAP Explainability</div>
                  <SHAPChart shapData={selectedAlert.shap_values} />
                </div>
                <div style={styles.card}>
                  <div style={styles.cardTitle}><span>🗺️</span> MITRE ATT&amp;CK</div>
                  <MITREPanel mitre={selectedAlert.mitre} />
                </div>
              </div>
            )}

            <div style={styles.card}>
              <div style={styles.cardTitle}><span>📡</span> Live Detection Feed</div>
              <LiveFeed apiUrl={API_URL} authHeaders={headers} refreshKey={refreshKey} />
            </div>
          </div>
        )}

        {activeTab === 'analytics' && (
          <AnalyticsDashboard authHeaders={headers} externalAlerts={allResults} />
        )}
      </main>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login"         element={<Login />} />
        <Route path="/register"      element={<Register />} />
        <Route path="/dashboard"     element={<Dashboard />} />
        <Route path="/auth/callback" element={<OAuthCallback />} />
        <Route path="/"              element={<Navigate to="/login" replace />} />
      </Routes>
    </BrowserRouter>
  );
}