# evaluate.py
# Usage: python evaluate.py
# Needs inventory.csv (from ics_vista2.py) and ground_truth.csv (ip,true_role)
import sys
import pandas as pd

inv = pd.read_csv("inventory.csv")
gt = pd.read_csv("ground_truth.csv")

VALID_ROLES = {"field_controller", "supervisory", "engineering_workstation"}
gt["ip"] = gt["ip"].astype(str).str.strip()
gt["true_role"] = gt["true_role"].fillna("").astype(str).str.strip()
bad = gt[~gt["true_role"].isin(VALID_ROLES)]
if len(bad):
    print(f"ERROR: {len(bad)} row(s) in the ground truth have a missing or invalid true_role.")
    print(bad.head(10).to_string(index=False))
    print("Valid roles:", ", ".join(sorted(VALID_ROLES)))
    print("Fill in true_role for every device (from Wireshark), then run again.")
    sys.exit(1)

# ---------- 1. Discovery ----------
found, true = set(inv["ip"]), set(gt["ip"])
tp = len(found & true)
fp = len(found - true)
fn = len(true - found)
precision = tp / (tp + fp) if (tp + fp) else 0.0
recall = tp / (tp + fn) if (tp + fn) else 0.0

print("=== Discovery ===")
print(f"True devices: {len(true)}  Found: {len(found)}")
print(f"TP={tp}  FP={fp}  FN={fn}")
print(f"Precision: {precision:.2f}   Recall: {recall:.2f}")
if fp:
    print("False positives (found but not in ground truth):", sorted(found - true))
if fn:
    print("Missed devices:", sorted(true - found))

# ---------- 2. Role classification ----------
m = gt.merge(inv[["ip", "predicted_role"]], on="ip", how="inner")
accuracy = (m["true_role"] == m["predicted_role"]).mean() if len(m) else 0.0

print("\n=== Role classification ===")
print(f"Devices evaluated: {len(m)}")
print(f"Accuracy: {accuracy:.2f}")

print("\nConfusion matrix (rows = true, columns = predicted):")
print(pd.crosstab(m["true_role"], m["predicted_role"]))

print("\nPer-class metrics:")
rows = []
for role in sorted(set(m["true_role"]) | set(m["predicted_role"])):
    tp_ = ((m["true_role"] == role) & (m["predicted_role"] == role)).sum()
    fp_ = ((m["true_role"] != role) & (m["predicted_role"] == role)).sum()
    fn_ = ((m["true_role"] == role) & (m["predicted_role"] != role)).sum()
    p = tp_ / (tp_ + fp_) if (tp_ + fp_) else 0.0
    r = tp_ / (tp_ + fn_) if (tp_ + fn_) else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    rows.append({"role": role, "precision": round(p, 2),
                 "recall": round(r, 2), "f1": round(f1, 2)})
print(pd.DataFrame(rows).to_string(index=False))

wrong = m[m["true_role"] != m["predicted_role"]]
if len(wrong):
    print("\nMisclassified devices:")
    print(wrong.to_string(index=False))

m.to_csv("evaluation_results.csv", index=False)
print("\nSaved evaluation_results.csv")
