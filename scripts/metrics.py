
import joblib, numpy as np, pandas as pd
from tensorflow.keras.models import load_model
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix, roc_curve

scaler = joblib.load("backend/models/scaler.pkl")
fcols  = joblib.load("backend/models/feature_columns.pkl")
ae = load_model("backend/models/autoencoder.h5", compile=False)

NSL_COLS = ["duration","protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins","logged_in","num_compromised","root_shell","su_attempted","num_root","num_file_creations","num_shells","num_access_files","num_outbound_cmds","is_host_login","is_guest_login","count","srv_count","serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate","dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty"]
df = pd.read_csv(r"data\nsl-kdd\KDDTest+.txt", header=None, names=NSL_COLS)
def normalize_label(label):
    label = str(label).lower().strip().rstrip(".")
    if label == "normal": return "Benign"
    if label in {"back","land","neptune","pod","teardrop","apache2","udpstorm","processtable","worm"}: return "DoS"
    if label in {"ipsweep","nmap","portsweep","satan","mscan","saint"}: return "PortScan"
    if label in {"ftp_write","guess_passwd","imap","multihop","phf","spy","warezclient","warezmaster","xlock","xsnoop","snmpguess","snmpgetattack","httptunnel","sendmail","named"}: return "BruteForce"
    if label in {"buffer_overflow","loadmodule","perl","rootkit","ps","sqlattack","xterm"}: return "Exploit"
    return "Unknown"
df["label"] = df["label"].apply(normalize_label)
df = df[df["label"] != "Unknown"].copy()
if "difficulty" in df.columns: df.drop(columns=["difficulty"], inplace=True)
df = pd.get_dummies(df, columns=["protocol_type","service","flag"], dtype=np.float32)
X = df[[c for c in df.columns if c != "label"]].reindex(columns=fcols, fill_value=0).apply(pd.to_numeric, errors="coerce").fillna(0).astype(np.float32)
y_true_binary = (df["label"] != "Benign").astype(int)
X_scaled = scaler.transform(X)

recon = ae.predict(X_scaled, verbose=0)
mse   = np.mean((X_scaled - recon)**2, axis=1)

# Optimal threshold via Youden's J
fpr, tpr, thresholds = roc_curve(y_true_binary, mse)
j = tpr - fpr
best_thresh = thresholds[np.argmax(j)]
print(f"Optimal threshold (Youden's J): {best_thresh:.4f}")

y_pred = (mse > best_thresh).astype(int)
print("\n========== Autoencoder Metrics ==========")
print(classification_report(y_true_binary, y_pred, target_names=["Benign","Attack"], digits=4))
print("\nConfusion Matrix (Benign=0, Attack=1):")
print(confusion_matrix(y_true_binary, y_pred))
print(f"\nAUC-ROC: {roc_auc_score(y_true_binary, mse):.4f}")
print(f"\nMean reconstruction error — Benign: {mse[y_true_binary==0].mean():.4f}")
print(f"Mean reconstruction error — Attack: {mse[y_true_binary==1].mean():.4f}")
