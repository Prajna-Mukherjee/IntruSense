import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import brainBg from "../assets/brain_bg.png";

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

export default function Register() {
  const [name,     setName]     = useState("");
  const [email,    setEmail]    = useState("");
  const [password, setPassword] = useState("");
  const [confirm,  setConfirm]  = useState("");
  const [showPass, setShowPass] = useState(false);
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState("");
  const [mounted,  setMounted]  = useState(false);
  const navigate = useNavigate();

  useEffect(() => { setMounted(true); }, []);

  const strength = getPasswordStrength(password);

  const handleRegister = async (e) => {
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
      const res = await fetch(`${API_URL}/auth/register`, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ email, password, name })
      });
      const data = await res.json();

      if (!res.ok) {
        setError(data.detail || "Registration failed.");
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

  return (
    <div style={{
      minHeight: "100vh", display: "flex",
      fontFamily: "'Rajdhani', sans-serif",
      background: "#050a14", overflow: "hidden"
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;500;600;700&family=Orbitron:wght@700;900&family=JetBrains+Mono:wght@400;500&display=swap');
        @keyframes slideIn { from { opacity:0; transform:translateX(40px); } to { opacity:1; transform:translateX(0); } }
        @keyframes fadeUp  { from { opacity:0; transform:translateY(16px); } to { opacity:1; transform:translateY(0); } }
        @keyframes scanline { 0% { top:-4px; } 100% { top:100%; } }
        @keyframes hexPulse { 0%,100% { opacity:.8; transform:scale(1); } 50% { opacity:1; transform:scale(1.04); } }
        @keyframes spin { to { transform:rotate(360deg); } }
        .reg-input {
          width:100%; background:rgba(255,255,255,0.04);
          border:1px solid rgba(0,212,255,0.25); border-radius:10px;
          padding:14px 16px 14px 46px; color:#e2e8f0;
          font-family:'JetBrains Mono',monospace; font-size:13px;
          outline:none; transition:all 0.3s; box-sizing:border-box;
        }
        .reg-input::placeholder { color:#475569; }
        .reg-input:focus {
          border-color:rgba(0,212,255,0.7);
          background:rgba(0,212,255,0.06);
          box-shadow:0 0 20px rgba(0,212,255,0.12);
        }
        .reg-btn {
          width:100%; padding:15px;
          background:linear-gradient(135deg,#0284c7 0%,#2563eb 50%,#7c3aed 100%);
          border:none; border-radius:10px; color:#fff;
          font-family:'Orbitron',sans-serif; font-size:14px;
          font-weight:700; letter-spacing:3px; cursor:pointer; transition:all 0.3s;
        }
        .reg-btn:hover:not(:disabled) { transform:translateY(-1px); box-shadow:0 8px 30px rgba(37,99,235,0.45); }
        .reg-btn:disabled { opacity:0.7; cursor:not-allowed; }
      `}</style>

      {/* ── Left image panel ── */}
      <div style={{ flex: "0 0 58%", position: "relative", overflow: "hidden" }}>
        <img src={brainBg} alt="IntruSense background"
          style={{ width:"100%", height:"100%", objectFit:"cover", objectPosition:"center", display:"block" }} />
        <div style={{
          position:"absolute", inset:0,
          background:"linear-gradient(to right, transparent 60%, rgba(8,15,30,0.85) 100%)",
          pointerEvents:"none"
        }} />
        <div style={{
          position:"absolute", left:0, right:0, height:3,
          background:"linear-gradient(transparent,rgba(0,212,255,0.12),transparent)",
          animation:"scanline 7s linear infinite", pointerEvents:"none"
        }} />
        <div style={{
          position:"absolute", bottom:36, left:36, right:60,
          background:"rgba(5,10,20,0.65)", backdropFilter:"blur(14px)",
          border:"1px solid rgba(0,212,255,0.2)", borderRadius:"12px",
          padding:"14px 18px", display:"flex", alignItems:"center", gap:14
        }}>
          <div style={{
            width:38, height:38, borderRadius:"50%", flexShrink:0,
            background:"linear-gradient(135deg,#0284c7,#7c3aed)",
            display:"flex", alignItems:"center", justifyContent:"center", fontSize:18
          }}>🛡️</div>
          <div>
            <div style={{ fontFamily:"'Orbitron',sans-serif", fontSize:11, fontWeight:700, color:"#00d4ff", letterSpacing:2 }}>
              AI POWERED. THREAT AWARE.
            </div>
            <div style={{ fontSize:12, color:"#64748b", marginTop:2 }}>
              Intelligent Detection. Real-time Protection.
            </div>
          </div>
        </div>
      </div>

      {/* ── Right register form ── */}
      <div style={{
        flex:"0 0 42%", display:"flex", flexDirection:"column",
        alignItems:"center", justifyContent:"center",
        background:"linear-gradient(160deg,#080f1e 0%,#0a1220 100%)",
        padding:"40px 48px", position:"relative",
        borderLeft:"1px solid rgba(0,212,255,0.08)",
        animation: mounted ? "slideIn 0.55s ease forwards" : "none"
      }}>
        <div style={{ width:"100%", maxWidth:380 }}>

          {/* Logo */}
          <div style={{ textAlign:"center", marginBottom:28, animation:"fadeUp 0.6s 0.1s both" }}>
            <div style={{
              width:68, height:68, margin:"0 auto 14px",
              background:"linear-gradient(135deg,rgba(2,132,199,0.2),rgba(124,58,237,0.2))",
              border:"1.5px solid rgba(0,212,255,0.4)", borderRadius:"16px",
              display:"flex", alignItems:"center", justifyContent:"center",
              fontSize:30, animation:"hexPulse 3s ease-in-out infinite",
              boxShadow:"0 0 28px rgba(0,212,255,0.15)"
            }}>🧠</div>
            <h1 style={{
              fontFamily:"'Orbitron',sans-serif", fontSize:26, fontWeight:900,
              margin:"0 0 5px", letterSpacing:1,
              background:"linear-gradient(135deg,#00d4ff,#2563eb,#a855f7)",
              WebkitBackgroundClip:"text", WebkitTextFillColor:"transparent", backgroundClip:"text"
            }}>IntruSense</h1>
            <p style={{ fontFamily:"'Rajdhani',sans-serif", fontSize:11, color:"#475569", margin:0, letterSpacing:2, textTransform:"uppercase" }}>
              Create your account
            </p>
          </div>

          {/* Form */}
          <form onSubmit={handleRegister} style={{ display:"flex", flexDirection:"column", gap:12, animation:"fadeUp 0.6s 0.2s both" }}>

            {/* Full name */}
            <div style={{ position:"relative" }}>
              <span style={{ position:"absolute", left:14, top:"50%", transform:"translateY(-50%)", color:"#475569", fontSize:15, pointerEvents:"none" }}>👤</span>
              <input type="text" placeholder="Full Name" value={name}
                onChange={e => setName(e.target.value)} className="reg-input" required />
            </div>

            {/* Email */}
            <div style={{ position:"relative" }}>
              <span style={{ position:"absolute", left:14, top:"50%", transform:"translateY(-50%)", color:"#475569", fontSize:15, pointerEvents:"none" }}>✉️</span>
              <input type="email" placeholder="Email Address" value={email}
                onChange={e => setEmail(e.target.value)} className="reg-input" required />
            </div>

            {/* Password */}
            <div style={{ position:"relative" }}>
              <span style={{ position:"absolute", left:14, top:"50%", transform:"translateY(-50%)", color:"#475569", fontSize:15, pointerEvents:"none" }}>🔒</span>
              <input type={showPass ? "text" : "password"} placeholder="Password"
                value={password} onChange={e => setPassword(e.target.value)}
                className="reg-input" required style={{ paddingRight:46 }} />
              <button type="button" onClick={() => setShowPass(v => !v)} style={{
                position:"absolute", right:14, top:"50%", transform:"translateY(-50%)",
                background:"none", border:"none", color:"#475569", cursor:"pointer", fontSize:15, padding:0
              }}>{showPass ? "🙈" : "👁️"}</button>
            </div>

            {/* Password strength meter */}
            {password && (
              <div style={{ padding:"10px 12px", background:"rgba(0,0,0,0.2)", borderRadius:8, border:"1px solid rgba(255,255,255,0.06)" }}>
                <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:8 }}>
                  <div style={{ flex:1, height:4, background:"#1e293b", borderRadius:2, overflow:"hidden" }}>
                    <div style={{
                      height:"100%", borderRadius:2, transition:"all 0.3s",
                      width:`${(strength.score / 5) * 100}%`,
                      background: strength.color
                    }} />
                  </div>
                  <span style={{ fontSize:11, color: strength.color, fontFamily:"'JetBrains Mono',monospace", minWidth:70 }}>
                    {strength.label}
                  </span>
                </div>
                <div style={{ display:"flex", flexDirection:"column", gap:4 }}>
                  {strength.checks.map((c, i) => (
                    <div key={i} style={{ display:"flex", alignItems:"center", gap:6 }}>
                      <span style={{ fontSize:11, color: c.pass ? "#22c55e" : "#475569" }}>
                        {c.pass ? "✓" : "○"}
                      </span>
                      <span style={{ fontSize:11, color: c.pass ? "#94a3b8" : "#475569", fontFamily:"'Rajdhani',sans-serif" }}>
                        {c.label}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Confirm password */}
            <div style={{ position:"relative" }}>
              <span style={{ position:"absolute", left:14, top:"50%", transform:"translateY(-50%)", color:"#475569", fontSize:15, pointerEvents:"none" }}>🔒</span>
              <input type={showPass ? "text" : "password"} placeholder="Confirm Password"
                value={confirm} onChange={e => setConfirm(e.target.value)}
                className="reg-input" required />
            </div>

            {/* Confirm match indicator */}
            {confirm && (
              <div style={{ fontSize:12, fontFamily:"'Rajdhani',sans-serif", color: password === confirm ? "#22c55e" : "#ef4444", paddingLeft:4 }}>
                {password === confirm ? "✓ Passwords match" : "✗ Passwords do not match"}
              </div>
            )}

            {/* Error */}
            {error && (
              <div style={{
                background:"rgba(239,68,68,0.1)", border:"1px solid rgba(239,68,68,0.4)",
                borderRadius:"8px", padding:"10px 14px", fontSize:"13px", color:"#f87171",
                fontFamily:"'Rajdhani',sans-serif"
              }}>⚠️ {error}</div>
            )}

            {/* Submit */}
            <button type="submit" className="reg-btn" disabled={loading}>
              {loading ? (
                <span style={{ display:"flex", alignItems:"center", justifyContent:"center", gap:10 }}>
                  <span style={{
                    width:15, height:15, border:"2px solid rgba(255,255,255,0.3)",
                    borderTopColor:"#fff", borderRadius:"50%",
                    animation:"spin 0.8s linear infinite", display:"inline-block"
                  }} />
                  CREATING ACCOUNT...
                </span>
              ) : "CREATE ACCOUNT"}
            </button>
          </form>

          {/* Back to login */}
          <p style={{
            textAlign:"center", marginTop:22, fontSize:13, color:"#334155",
            fontFamily:"'Rajdhani',sans-serif", animation:"fadeUp 0.6s 0.4s both"
          }}>
            Already have an account?{" "}
            <button onClick={() => navigate("/login")} style={{
              background:"none", border:"none", color:"#0284c7",
              fontSize:13, cursor:"pointer", fontWeight:700,
              fontFamily:"'Rajdhani',sans-serif", padding:0
            }}>Sign In</button>
          </p>
        </div>

        <p style={{
          position:"absolute", bottom:18, fontSize:11, color:"#1e293b",
          fontFamily:"'JetBrains Mono',monospace", letterSpacing:1, margin:0
        }}>© 2026 IntruSense AI NIDS. All rights reserved.</p>
      </div>
    </div>
  );
}