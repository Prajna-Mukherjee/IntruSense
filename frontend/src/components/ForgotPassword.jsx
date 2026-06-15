import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";

const API_URL = process.env.REACT_APP_API_URL || "http://localhost:8000";

export default function ForgotPassword() {
  const [email,   setEmail]   = useState("");
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [error,   setError]   = useState("");
  const [mounted, setMounted] = useState(false);
  const navigate = useNavigate();

  useEffect(() => { setMounted(true); }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setMessage("");
    setLoading(true);

    try {
      const res  = await fetch(`${API_URL}/auth/forgot-password`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ email: email.trim() })
      });
      const data = await res.json();

      if (!res.ok) {
        setError(data.detail || "Something went wrong. Please try again.");
      } else {
        setMessage(data.message);
      }
    } catch {
      setError("Could not connect to server. Is the backend running?");
    }

    setLoading(false);
  };

  return (
    <div style={{
      minHeight: "100vh", display: "flex",
      alignItems: "center", justifyContent: "center",
      background: "#050a14", fontFamily: "'Rajdhani', sans-serif"
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;500;600;700&family=Orbitron:wght@700;900&family=JetBrains+Mono:wght@400;500&display=swap');
        @keyframes fadeUp { from { opacity:0; transform:translateY(16px); } to { opacity:1; transform:translateY(0); } }
        @keyframes spin { to { transform:rotate(360deg); } }
        .fp-input {
          width:100%; background:rgba(255,255,255,0.04);
          border:1px solid rgba(0,212,255,0.25); border-radius:10px;
          padding:14px 16px 14px 46px; color:#e2e8f0;
          font-family:'JetBrains Mono',monospace; font-size:13px;
          outline:none; transition:all 0.3s; box-sizing:border-box;
        }
        .fp-input::placeholder { color:#475569; }
        .fp-input:focus {
          border-color:rgba(0,212,255,0.7);
          background:rgba(0,212,255,0.06);
          box-shadow:0 0 20px rgba(0,212,255,0.12);
        }
        .fp-btn {
          width:100%; padding:15px;
          background:linear-gradient(135deg,#0284c7 0%,#2563eb 50%,#7c3aed 100%);
          border:none; border-radius:10px; color:#fff;
          font-family:'Orbitron',sans-serif; font-size:14px;
          font-weight:700; letter-spacing:3px; cursor:pointer; transition:all 0.3s;
        }
        .fp-btn:hover:not(:disabled) { transform:translateY(-1px); box-shadow:0 8px 30px rgba(37,99,235,0.45); }
        .fp-btn:disabled { opacity:0.7; cursor:not-allowed; }
      `}</style>

      <div style={{
        width: "100%", maxWidth: 420,
        background: "linear-gradient(160deg,#080f1e 0%,#0a1220 100%)",
        border: "1px solid rgba(0,212,255,0.08)",
        borderRadius: 16, padding: "40px 36px",
        animation: mounted ? "fadeUp 0.5s ease forwards" : "none"
      }}>

        {/* Logo */}
        <div style={{ textAlign: "center", marginBottom: 28 }}>
          <div style={{
            width: 60, height: 60, margin: "0 auto 14px",
            background: "linear-gradient(135deg,rgba(2,132,199,0.2),rgba(124,58,237,0.2))",
            border: "1.5px solid rgba(0,212,255,0.4)", borderRadius: "14px",
            display: "flex", alignItems: "center", justifyContent: "center", fontSize: 26
          }}>🔐</div>
          <h1 style={{
            fontFamily: "'Orbitron',sans-serif", fontSize: 22, fontWeight: 900,
            margin: "0 0 6px",
            background: "linear-gradient(135deg,#00d4ff,#2563eb,#a855f7)",
            WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", backgroundClip: "text"
          }}>Forgot Password</h1>
          <p style={{ fontSize: 13, color: "#475569", margin: 0 }}>
            Enter your email and we will send you a reset link
          </p>
        </div>

        {/* Success state */}
        {message ? (
          <div>
            <div style={{
              background: "rgba(34,197,94,0.1)", border: "1px solid rgba(34,197,94,0.4)",
              borderRadius: 8, padding: "14px 16px", fontSize: 13,
              color: "#86efac", fontFamily: "'Rajdhani',sans-serif",
              textAlign: "center", lineHeight: 1.6
            }}>
              ✅ {message}
            </div>
            <p style={{ textAlign: "center", marginTop: 20, fontSize: 13, color: "#475569" }}>
              Check your inbox and spam folder.
              <br />The link expires in <span style={{ color: "#00d4ff" }}>30 minutes</span>.
            </p>
            <button
              onClick={() => navigate("/login")}
              style={{
                width: "100%", marginTop: 16, padding: "12px",
                background: "transparent",
                border: "1px solid rgba(0,212,255,0.3)",
                borderRadius: 10, color: "#00d4ff",
                fontFamily: "'Rajdhani',sans-serif",
                fontSize: 14, fontWeight: 600,
                cursor: "pointer", transition: "all 0.2s"
              }}
            >
              Back to Login
            </button>
          </div>
        ) : (
          <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: 14 }}>

            {/* Email input */}
            <div style={{ position: "relative" }}>
              <span style={{
                position: "absolute", left: 14, top: "50%",
                transform: "translateY(-50%)", color: "#475569",
                fontSize: 15, pointerEvents: "none"
              }}>✉️</span>
              <input
                type="email"
                placeholder="Your registered email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                className="fp-input"
                required
              />
            </div>

            {/* Error */}
            {error && (
              <div style={{
                background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.4)",
                borderRadius: 8, padding: "10px 14px", fontSize: 13,
                color: "#f87171", fontFamily: "'Rajdhani',sans-serif"
              }}>⚠️ {error}</div>
            )}

            {/* Submit */}
            <button type="submit" className="fp-btn" disabled={loading}>
              {loading ? (
                <span style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 10 }}>
                  <span style={{
                    width: 15, height: 15,
                    border: "2px solid rgba(255,255,255,0.3)",
                    borderTopColor: "#fff", borderRadius: "50%",
                    animation: "spin 0.8s linear infinite", display: "inline-block"
                  }} />
                  SENDING...
                </span>
              ) : "SEND RESET LINK"}
            </button>

            {/* Back to login */}
            <p style={{ textAlign: "center", fontSize: 13, color: "#334155", margin: 0 }}>
              Remembered it?{" "}
              <button
                type="button"
                onClick={() => navigate("/login")}
                style={{
                  background: "none", border: "none", color: "#0284c7",
                  fontSize: 13, cursor: "pointer", fontWeight: 700,
                  fontFamily: "'Rajdhani',sans-serif", padding: 0
                }}
              >Back to Login</button>
            </p>
          </form>
        )}
      </div>
    </div>
  );
}