import { useState, useEffect } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

const API_URL = process.env.REACT_APP_API_URL || "http://localhost:8000";

function getPasswordStrength(password) {
  if (!password) return { score: 0, label: "", color: "#334155", checks: [] };
  const checks = [
    { label: "At least 8 characters",        pass: password.length >= 8 },
    { label: "Uppercase letter (A-Z)",        pass: /[A-Z]/.test(password) },
    { label: "Lowercase letter (a-z)",        pass: /[a-z]/.test(password) },
    { label: "Number (0-9)",                  pass: /\d/.test(password) },
    { label: "Special character (!@#$ etc)",  pass: /[!@#$%^&*()\-_=+\[\]{}|;':",.<>?`~\\]/.test(password) },
  ];
  const score  = checks.filter(c => c.pass).length;
  const labels = ["", "Very Weak", "Weak", "Fair", "Strong", "Very Strong"];
  const colors = ["#334155", "#ef4444", "#f97316", "#eab308", "#22c55e", "#00d4ff"];
  return { score, label: labels[score], color: colors[score], checks };
}

export default function ResetPassword() {
  const [searchParams]          = useSearchParams();
  const [password,  setPassword] = useState("");
  const [confirm,   setConfirm]  = useState("");
  const [showPass,  setShowPass] = useState(false);
  const [loading,   setLoading]  = useState(false);
  const [verifying, setVerifying] = useState(true);
  const [tokenValid, setTokenValid] = useState(false);
  const [success,   setSuccess]  = useState(false);
  const [error,     setError]    = useState("");
  const [mounted,   setMounted]  = useState(false);
  const navigate = useNavigate();
  const token = searchParams.get("token");

  useEffect(() => { setMounted(true); }, []);

  // Verify the token is still valid when the page loads
  useEffect(() => {
    if (!token) {
      setError("No reset token found. Please request a new password reset link.");
      setVerifying(false);
      return;
    }

    fetch(`${API_URL}/auth/verify-reset-token?token=${encodeURIComponent(token)}`)
      .then(res => {
        if (!res.ok) throw new Error("Invalid token");
        return res.json();
      })
      .then(() => {
        setTokenValid(true);
        setVerifying(false);
      })
      .catch(() => {
        setError("This reset link is invalid or has expired. Please request a new one.");
        setVerifying(false);
      });
  }, [token]);

  const strength = getPasswordStrength(password);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");

    if (password !== confirm) {
      setError("Passwords do not match.");
      return;
    }

    if (strength.score < 5) {
      setError("Please meet all password requirements before continuing.");
      return;
    }

    setLoading(true);

    try {
      const res  = await fetch(`${API_URL}/auth/reset-password`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ token, password })
      });
      const data = await res.json();

      if (!res.ok) {
        setError(data.detail || "Password reset failed. Please try again.");
      } else {
        setSuccess(true);
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
        .rp-input {
          width:100%; background:rgba(255,255,255,0.04);
          border:1px solid rgba(0,212,255,0.25); border-radius:10px;
          padding:14px 16px 14px 46px; color:#e2e8f0;
          font-family:'JetBrains Mono',monospace; font-size:13px;
          outline:none; transition:all 0.3s; box-sizing:border-box;
        }
        .rp-input::placeholder { color:#475569; }
        .rp-input:focus {
          border-color:rgba(0,212,255,0.7);
          background:rgba(0,212,255,0.06);
          box-shadow:0 0 20px rgba(0,212,255,0.12);
        }
        .rp-btn {
          width:100%; padding:15px;
          background:linear-gradient(135deg,#0284c7 0%,#2563eb 50%,#7c3aed 100%);
          border:none; border-radius:10px; color:#fff;
          font-family:'Orbitron',sans-serif; font-size:14px;
          font-weight:700; letter-spacing:3px; cursor:pointer; transition:all 0.3s;
        }
        .rp-btn:hover:not(:disabled) { transform:translateY(-1px); box-shadow:0 8px 30px rgba(37,99,235,0.45); }
        .rp-btn:disabled { opacity:0.7; cursor:not-allowed; }
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
          }}>🔑</div>
          <h1 style={{
            fontFamily: "'Orbitron',sans-serif", fontSize: 22, fontWeight: 900,
            margin: "0 0 6px",
            background: "linear-gradient(135deg,#00d4ff,#2563eb,#a855f7)",
            WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", backgroundClip: "text"
          }}>Reset Password</h1>
          <p style={{ fontSize: 13, color: "#475569", margin: 0 }}>
            Enter your new password below
          </p>
        </div>

        {/* Verifying token */}
        {verifying && (
          <div style={{ textAlign: "center", color: "#64748b", fontSize: 13 }}>
            <span style={{
              display: "inline-block", width: 20, height: 20,
              border: "2px solid rgba(0,212,255,0.3)",
              borderTopColor: "#00d4ff", borderRadius: "50%",
              animation: "spin 0.8s linear infinite"
            }} />
            <p style={{ marginTop: 12 }}>Verifying reset link...</p>
          </div>
        )}

        {/* Invalid token */}
        {!verifying && !tokenValid && !success && (
          <div>
            <div style={{
              background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.4)",
              borderRadius: 8, padding: "14px 16px", fontSize: 13,
              color: "#f87171", fontFamily: "'Rajdhani',sans-serif",
              textAlign: "center", lineHeight: 1.6
            }}>
              ⚠️ {error}
            </div>
            <button
              onClick={() => navigate("/forgot-password")}
              style={{
                width: "100%", marginTop: 16, padding: "13px",
                background: "linear-gradient(135deg,#0284c7,#2563eb,#7c3aed)",
                border: "none", borderRadius: 10, color: "#fff",
                fontFamily: "'Orbitron',sans-serif", fontSize: 13,
                fontWeight: 700, letterSpacing: 2, cursor: "pointer"
              }}
            >
              REQUEST NEW LINK
            </button>
          </div>
        )}

        {/* Success */}
        {success && (
          <div>
            <div style={{
              background: "rgba(34,197,94,0.1)", border: "1px solid rgba(34,197,94,0.4)",
              borderRadius: 8, padding: "14px 16px", fontSize: 13,
              color: "#86efac", fontFamily: "'Rajdhani',sans-serif",
              textAlign: "center", lineHeight: 1.6
            }}>
              ✅ Password reset successfully!
            </div>
            <p style={{ textAlign: "center", marginTop: 16, fontSize: 13, color: "#475569" }}>
              You can now log in with your new password.
            </p>
            <button
              onClick={() => navigate("/login")}
              style={{
                width: "100%", marginTop: 8, padding: "13px",
                background: "linear-gradient(135deg,#0284c7,#2563eb,#7c3aed)",
                border: "none", borderRadius: 10, color: "#fff",
                fontFamily: "'Orbitron',sans-serif", fontSize: 13,
                fontWeight: 700, letterSpacing: 2, cursor: "pointer"
              }}
            >
              GO TO LOGIN
            </button>
          </div>
        )}

        {/* Reset form */}
        {!verifying && tokenValid && !success && (
          <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: 14 }}>

            {/* New password */}
            <div style={{ position: "relative" }}>
              <span style={{
                position: "absolute", left: 14, top: "50%",
                transform: "translateY(-50%)", color: "#475569",
                fontSize: 15, pointerEvents: "none"
              }}>🔒</span>
              <input
                type={showPass ? "text" : "password"}
                placeholder="New password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                className="rp-input"
                required
                style={{ paddingRight: 46 }}
              />
              <button
                type="button"
                onClick={() => setShowPass(v => !v)}
                style={{
                  position: "absolute", right: 14, top: "50%",
                  transform: "translateY(-50%)", background: "none",
                  border: "none", color: "#475569", cursor: "pointer",
                  fontSize: 15, padding: 0
                }}
              >{showPass ? "🙈" : "👁️"}</button>
            </div>

            {/* Password strength meter */}
            {password && (
              <div style={{
                padding: "10px 12px", background: "rgba(0,0,0,0.2)",
                borderRadius: 8, border: "1px solid rgba(255,255,255,0.06)"
              }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                  <div style={{ flex: 1, height: 4, background: "#1e293b", borderRadius: 2, overflow: "hidden" }}>
                    <div style={{
                      height: "100%", borderRadius: 2, transition: "all 0.3s",
                      width: `${(strength.score / 5) * 100}%`,
                      background: strength.color
                    }} />
                  </div>
                  <span style={{ fontSize: 11, color: strength.color, fontFamily: "'JetBrains Mono',monospace", minWidth: 70 }}>
                    {strength.label}
                  </span>
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  {strength.checks.map((c, i) => (
                    <div key={i} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <span style={{ fontSize: 11, color: c.pass ? "#22c55e" : "#475569" }}>
                        {c.pass ? "✓" : "○"}
                      </span>
                      <span style={{ fontSize: 11, color: c.pass ? "#94a3b8" : "#475569", fontFamily: "'Rajdhani',sans-serif" }}>
                        {c.label}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Confirm password */}
            <div style={{ position: "relative" }}>
              <span style={{
                position: "absolute", left: 14, top: "50%",
                transform: "translateY(-50%)", color: "#475569",
                fontSize: 15, pointerEvents: "none"
              }}>🔒</span>
              <input
                type={showPass ? "text" : "password"}
                placeholder="Confirm new password"
                value={confirm}
                onChange={e => setConfirm(e.target.value)}
                className="rp-input"
                required
              />
            </div>

            {/* Confirm match indicator */}
            {confirm && (
              <div style={{
                fontSize: 12, fontFamily: "'Rajdhani',sans-serif",
                color: password === confirm ? "#22c55e" : "#ef4444", paddingLeft: 4
              }}>
                {password === confirm ? "✓ Passwords match" : "✗ Passwords do not match"}
              </div>
            )}

            {/* Error */}
            {error && (
              <div style={{
                background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.4)",
                borderRadius: 8, padding: "10px 14px", fontSize: 13,
                color: "#f87171", fontFamily: "'Rajdhani',sans-serif"
              }}>⚠️ {error}</div>
            )}

            {/* Submit */}
            <button type="submit" className="rp-btn" disabled={loading}>
              {loading ? (
                <span style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: 10 }}>
                  <span style={{
                    width: 15, height: 15,
                    border: "2px solid rgba(255,255,255,0.3)",
                    borderTopColor: "#fff", borderRadius: "50%",
                    animation: "spin 0.8s linear infinite", display: "inline-block"
                  }} />
                  RESETTING...
                </span>
              ) : "RESET PASSWORD"}
            </button>

            <p style={{ textAlign: "center", fontSize: 13, color: "#334155", margin: 0 }}>
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