"""
scan.py - local command-line XSS scanner (no network, nothing is executed or rendered).

  python scan.py "<img src=x onerror=alert(1)>"       # scan one payload
  python scan.py --file inputs.csv --column payload    # scan a CSV column, writes scan_results.csv
  python scan.py                                       # interactive mode (type payloads, empty line to quit)
"""
import argparse, joblib, numpy as np, pandas as pd, scipy.sparse as sp
from features import safe_decode, feature_matrix, explain

BUNDLE = joblib.load("models/xss_model.joblib")

def score(texts):
    dec = [safe_decode(t)[0] for t in texts]
    X = sp.hstack([BUNDLE["tfidf"].transform(dec), sp.csr_matrix(BUNDLE["scaler"].transform(feature_matrix(texts)))]).tocsr()
    return BUNDLE["model"].predict_proba(X)[:, 1]

def severity(p):
    return "SAFE" if p < .30 else "LOW" if p < .50 else "MEDIUM" if p < .70 else "HIGH" if p < .90 else "CRITICAL"

def show(text, p):
    dec, layers = safe_decode(text)
    print(f"\nInput    : {text}")
    if layers: print(f"Decoded  : {dec}   ({layers} decoding layer(s))")
    print(f"Verdict  : {'XSS SUSPECTED' if p >= .5 else 'looks benign'}   (probability {p:.3f}, severity {severity(p)})")
    hits = explain(text)
    if hits:
        print("Signals  :"); [print(f"   - {n}: {d}") for n, d in hits]

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("payload", nargs="?"); ap.add_argument("--file"); ap.add_argument("--column", default="payload")
    a = ap.parse_args()
    if a.file:
        d = pd.read_csv(a.file); p = score(d[a.column].astype(str).tolist())
        d["xss_probability"] = np.round(p, 4); d["verdict"] = np.where(p >= .5, "XSS_SUSPECTED", "benign"); d["severity"] = [severity(x) for x in p]
        d.to_csv("scan_results.csv", index=False); print(f"Scanned {len(d)} rows -> scan_results.csv ({int((p >= .5).sum())} flagged)")
    elif a.payload:
        show(a.payload, score([a.payload])[0])
    else:
        print("Interactive mode - type a payload, empty line to quit.")
        while (t := input("> ")).strip(): show(t, score([t])[0])
