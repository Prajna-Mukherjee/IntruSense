import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import brainBg from "../assets/brain_bg.png";

const API_URL = process.env.REACT_APP_API_URL || "http://localhost:8000";

export default function Login() {
  const [email,    setEmail]    = useState("");
  const [password, setPassword] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [remember, setRemember] = useState(true);
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState("");
  const [mounted,  setMounted]  = useState(false);
  const navigate = useNavigate();

  useEffect(() => { setMounted(true); }, []);

  const handleLogin = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/auth/login`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ email: email.trim(), password }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.detail || "Login failed.");
        setLoading(false);
        return;
      }
      sessionStorage.setItem("intrusense_auth", data.token);
      sessionStorage.setItem("intrusense_name", data.name);
      navigate("/dashboard");
    } catch {
      setError("Could not connect to server. Is the backend running?");
      setLoading(false);
    }
  };

  const handleOAuth = (provider) => {
    window.location.href = `${API_URL}/auth/${provider.toLowerCase()}`;
  };

  return (
    <div style={{
      minHeight: "100vh", display: "flex",
      fontFamily: "'Rajdhani', 'sans-serif'",
      background: "#050a14", overflow: "hidden"
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;500;600;700&family=Orbitron:wght@700;900&family=JetBrains+Mono:wght@400;500&display=swap');
        @keyframes slideIn { from { opacity: 0; transform: translateX(40px); } to { opacity: 1; transform: translateX(0); } }
        @keyframes fadeUp { from { opacity: 0; transform: translateY(16px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes scanline { 0% { top: -4px; } 100% { top: 100%; } }
        @keyframes pulse-ring { 0% { box-shadow: 0 0 0 0 rgba(0,212,255,0.5); } 70% { box-shadow: 0 0 0 12px rgba(0,212,255,0); } 100% { box-shadow: 0 0 0 0 rgba(0,212,255,0); } }
        @keyframes hexPulse { 0%, 100% { opacity: 0.8; transform: scale(1); } 50% { opacity: 1; transform: scale(1.04); } }
        @keyframes spin { to { transform: rotate(360deg); } }
        .login-input {
          width: 100%; background: rgba(255,255,255,0.04);
          border: 1px solid rgba(0,212,255,0.25); border-radius: 10px;
          padding: 14px 16px 14px 46px; color: #e2e8f0;
          font-family: 'JetBrains Mono', monospace; font-size: 13px;
          outline: none; transition: all 0.3s; box-sizing: border-box;
        }
        .login-input::placeholder { color: #475569; }
        .login-input:focus {
          border-color: rgba(0,212,255,0.7); background: rgba(0,212,255,0.06);
          box-shadow: 0 0 20px rgba(0,212,255,0.12);
        }
        .login-btn {
          width: 100%; padding: 15px;
          background: linear-gradient(135deg, #0284c7 0%, #2563eb 50%, #7c3aed 100%);
          border: none; border-radius: 10px; color: #fff;
          font-family: 'Orbitron', sans-serif; font-size: 14px;
          font-weight: 700; letter-spacing: 3px; cursor: pointer; transition: all 0.3s;
        }
        .login-btn:hover:not(:disabled) { transform: translateY(-1px); box-shadow: 0 8px 30px rgba(37,99,235,0.45); }
        .login-btn:disabled { opacity: 0.7; cursor: not-allowed; }
        .oauth-btn {
          width: 100%; padding: 12px 16px;
          background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.1);
          border-radius: 10px; color: #cbd5e1;
          font-family: 'Rajdhani', sans-serif; font-size: 14px;
          font-weight: 600; letter-spacing: 0.8px; cursor: pointer;
          display: flex; align-items: center; justify-content: center; gap: 10px;
          transition: all 0.25s;
        }
        .oauth-btn:hover {
          background: rgba(255,255,255,0.08); border-color: rgba(0,212,255,0.4);
          color: #fff; transform: translateY(-1px);
        }
      `}</style>

      {/* ══ LEFT — image panel ══ */}
      <div style={{ flex: "0 0 58%", position: "relative", overflow: "hidden" }}>
        <img src={brainBg} alt="IntruSense AI background"
          style={{ width: "100%", height: "100%", objectFit: "cover", objectPosition: "center", display: "block" }} />
        <div style={{
          position: "absolute", inset: 0,
          background: "linear-gradient(to right, transparent 60%, rgba(8,15,30,0.85) 100%)",
          pointerEvents: "none"
        }} />
        <div style={{
          position: "absolute", left: 0, right: 0, height: 3,
          background: "linear-gradient(transparent, rgba(0,212,255,0.12), transparent)",
          animation: "scanline 7s linear infinite", pointerEvents: "none"
        }} />
        <div style={{
          position: "absolute", bottom: 36, left: 36, right: 60,
          background: "rgba(5,10,20,0.65)", backdropFilter: "blur(14px)",
          border: "1px solid rgba(0,212,255,0.2)", borderRadius: "12px",
          padding: "14px 18px", display: "flex", alignItems: "center", gap: 14
        }}>
          <div style={{
            width: 38, height: 38, borderRadius: "50%", flexShrink: 0,
            background: "linear-gradient(135deg, #0284c7, #7c3aed)",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 18, animation: "pulse-ring 2.5s ease-in-out infinite"
          }}>🛡️</div>
          <div>
            <div style={{ fontFamily: "'Orbitron', sans-serif", fontSize: 11, fontWeight: 700, color: "#00d4ff", letterSpacing: 2 }}>
              AI POWERED. THREAT AWARE.
            </div>
            <div style={{ fontSize: 12, color: "#64748b", marginTop: 2 }}>
              Intelligent Detection. Real-time Protection.
            </div>
          </div>
        </div>
      </div>

      {/* ══ RIGHT — login form ══ */}
      <div style={{
        flex: "0 0 42%", display: "flex", flexDirection: "column",
        alignItems: "center", justifyContent: "center",
        background: "linear-gradient(160deg, #080f1e 0%, #0a1220 100%)",
        padding: "40px 48px", position: "relative",
        borderLeft: "1px solid rgba(0,212,255,0.08)",
        animation: mounted ? "slideIn 0.55s ease forwards" : "none"
      }}>
        <div style={{ width: "100%", maxWidth: 380 }}>

          {/* Logo */}
          <div style={{ textAlign: "center", marginBottom: 32, animation: "fadeUp 0.6s 0.1s both" }}>
            <div style={{
              width: 68, height: 68, margin: "0 auto 14px",
              background: "linear-gradient(135deg, rgba(2,132,199,0.2), rgba(124,58,237,0.2))",
              border: "1.5px solid rgba(0,212,255,0.4)", borderRadius: "16px",
              display: "flex", alignItems: "center", justifyContent: "center",
              fontSize: 30, animation: "hexPulse 3s ease-in-out infinite",
              boxShadow: "0 0 28px rgba(0,212,255,0.15)"
            }}>🧠</div>
            <h1 style={{
              fontFamily: "'Orbitron', sans-serif", fontSize: 28, fontWeight: 900,
              margin: "0 0 5px", letterSpacing: 1,
              background: "linear-gradient(135deg, #00d4ff, #2563eb, #a855f7)",
              WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", backgroundClip: "text"
            }}>IntruSense</h1>
            <p style={{
              fontFamily: "'Rajdhani', sans-serif", fontSize: 11,
              color: "#475569", margin: 0, letterSpacing: 2, textTransform: "uppercase"
            }}>AI-Powered Network Intrusion Detection System</p>
          </div>

          {/* Welcome */}
          <div style={{ textAlign: "center", marginBottom: 26, animation: "fadeUp 0.6s 0.2s both" }}>
            <h2 style={{
              fontFamily: "'Rajdhani', sans-serif", fontSize: 22,
              fontWeight: 700, color: "#00d4ff", margin: "0 0 5px", letterSpacing: 1
            }}>Welcome Back</h2>
            <p style={{ fontSize: 13, color: "#475569", margin: 0 }}>
              Sign in to continue to your dashboard
            </p>
          </div>

          {/* Form */}
          <form onSubmit={handleLogin}
            style={{ display: "flex", flexDirection: "column", gap: 13, animation: "fadeUp 0.6s 0.3s both" }}>

            {/* Email */}
            <div style={{ position: "relative" }}>
              <span style={{
                position: "absolute", left: 14, top: "50%",
                transform: "translateY(-50%)", color: "#475569", fontSize: 15, pointerEvents: "none"
              }}>👤</span>
              <input type="email" placeholder="Email Address"
                value={email} onChange={e => setEmail(e.target.value)}
                className="login-input" required />
            </div>

            {/* Password */}
            <div style={{ position: "relative" }}>
              <span style={{
                position: "absolute", left: 14, top: "50%",
                transform: "translateY(-50%)", color: "#475569", fontSize: 15, pointerEvents: "none"
              }}>🔒</span>
              <input
                type={showPass ? "text" : "password"}
                placeholder="Password"
                value={password} onChange={e => setPassword(e.target.value)}
                className="login-input" required style={{ paddingRight: 46 }}
              />
              <button type="button" onClick={() => setShowPass(v => !v)} style={{
                position: "absolute", right: 14, top: "50%",
                transform: "translateY(-50%)", background: "none",
                border: "none", color: "#475569", cursor: "pointer", fontSize: 15, padding: 0
              }}>{showPass ? "🙈" : "👁️"}</button>
            </div>

            {/* Remember + Forgot */}
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <label style={{ display: "flex", alignItems: "center", gap: 8, cursor: "pointer" }}
                onClick={() => setRemember(v => !v)}>
                <div style={{
                  width: 16, height: 16, borderRadius: 4, flexShrink: 0,
                  border: "1.5px solid rgba(0,212,255,0.5)", transition: "all 0.2s",
                  background: remember ? "rgba(0,212,255,0.2)" : "transparent",
                  display: "flex", alignItems: "center", justifyContent: "center"
                }}>
                  {remember && <span style={{ color: "#00d4ff", fontSize: 11, fontWeight: 700 }}>✓</span>}
                </div>
                <span style={{ fontSize: 13, color: "#64748b", fontFamily: "'Rajdhani', sans-serif" }}>
                  Remember me
                </span>
              </label>

              {/* ── FIX: Forgot Password now navigates to the forgot password page ── */}
              <button
                type="button"
                onClick={() => navigate("/forgot-password")}
                style={{
                  background: "none", border: "none", color: "#0284c7",
                  fontSize: 13, cursor: "pointer",
                  fontFamily: "'Rajdhani', sans-serif", fontWeight: 600
                }}
              >Forgot Password?</button>
            </div>

            {/* Error */}
            {error && (
              <div style={{
                background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.4)",
                borderRadius: "8px", padding: "10px 14px", fontSize: "13px",
                color: "#f87171", fontFamily: "'Rajdhani', sans-serif"
              }}>⚠️ {error}</div>
            )}

            {/* Login button */}
            <button type="submit" className="login-btn" disabled={loading}>
              {loading ? (
                <span style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 10 }}>
                  <span style={{
                    width: 15, height: 15,
                    border: "2px solid rgba(255,255,255,0.3)",
                    borderTopColor: "#fff", borderRadius: "50%",
                    animation: "spin 0.8s linear infinite", display: "inline-block"
                  }} />
                  AUTHENTICATING...
                </span>
              ) : "LOGIN"}
            </button>
          </form>

          {/* Divider */}
          <div style={{
            display: "flex", alignItems: "center", gap: 12,
            margin: "20px 0", animation: "fadeUp 0.6s 0.4s both"
          }}>
            <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.07)" }} />
            <span style={{ fontSize: 11, color: "#334155", fontFamily: "'JetBrains Mono', monospace" }}>OR</span>
            <div style={{ flex: 1, height: 1, background: "rgba(255,255,255,0.07)" }} />
          </div>

          {/* OAuth */}
          <div style={{ display: "flex", flexDirection: "column", gap: 9, animation: "fadeUp 0.6s 0.5s both" }}>
            <button className="oauth-btn" onClick={() => handleOAuth("Google")}>
              <svg width="17" height="17" viewBox="0 0 24 24">
                <path fill="#4285f4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                <path fill="#34a853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                <path fill="#fbbc05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                <path fill="#ea4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
              </svg>
              Continue with Google
            </button>
          </div>

          {/* Register link */}
          <p style={{
            textAlign: "center", marginTop: 24, fontSize: 13, color: "#334155",
            fontFamily: "'Rajdhani', sans-serif", animation: "fadeUp 0.6s 0.6s both"
          }}>
            Don't have an account?{" "}
            <button style={{
              background: "none", border: "none", color: "#0284c7",
              fontSize: 13, cursor: "pointer", fontWeight: 700,
              fontFamily: "'Rajdhani', sans-serif", padding: 0
            }} onClick={() => navigate("/register")}>Create Account</button>
          </p>
        </div>

        <p style={{
          position: "absolute", bottom: 18, fontSize: 11, color: "#1e293b",
          fontFamily: "'JetBrains Mono', monospace", letterSpacing: 1, margin: 0
        }}>© 2026 IntruSense AI NIDS. All rights reserved.</p>
      </div>
    </div>
  );
}