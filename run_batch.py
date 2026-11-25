# run_batch.py
# Usage: python run_batch.py "C:\path\to\folder_with_pcaps"
# Runs run_all.py (without the slow scalability test) on every .pcap/.pcapng in the folder,
# then prints and saves one summary table: batch_summary.csv
# Datasets without a ground-truth file still get discovery + alerts; evaluation columns stay empty,
# and a ground-truth TEMPLATE is created for you to fill in from Wireshark.
import glob, os, re, subprocess, sys
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))

if len(sys.argv) < 2:
    sys.exit('Usage: python run_batch.py "<folder with pcap files>"')

folder = sys.argv[1]
pcaps = sorted(glob.glob(os.path.join(folder, "*.pcap")) + glob.glob(os.path.join(folder, "*.pcapng")))
if not pcaps:
    sys.exit(f"No .pcap or .pcapng files found in {folder}")

print(f"Found {len(pcaps)} capture(s):")
for p in pcaps:
    print("  ", os.path.basename(p))

for p in pcaps:
    print(f"\n{'#' * 70}\n# {os.path.basename(p)}\n{'#' * 70}", flush=True)
    subprocess.run([sys.executable, os.path.join(HERE, "run_all.py"), p, "--skip-scalability"])

rows = []
for p in pcaps:
    name = os.path.splitext(os.path.basename(p))[0]
    rdir = os.path.join(HERE, "results", name)
    row = {"dataset": name, "devices_found": "", "disc_precision": "", "disc_recall": "",
           "role_accuracy": "", "false_alerts": "", "alerts_per_hour": ""}
    inv = os.path.join(rdir, "inventory.csv")
    if os.path.exists(inv):
        row["devices_found"] = len(pd.read_csv(inv))
    log = os.path.join(rdir, "run_log.txt")
    if os.path.exists(log):
        text = open(log, encoding="utf-8", errors="replace").read()
        m = re.search(r"Precision:\s*([\d.]+)\s+Recall:\s*([\d.]+)", text)
        if m:
            row["disc_precision"], row["disc_recall"] = m.group(1), m.group(2)
        m = re.search(r"Total alerts:\s*(\d+)\s*\|.*alerts/hour:\s*([\d.]+)", text)
        if m:
            row["false_alerts"], row["alerts_per_hour"] = m.group(1), m.group(2)
    ev = os.path.join(rdir, "evaluation_results.csv")
    if os.path.exists(ev):
        d = pd.read_csv(ev)
        if len(d):
            row["role_accuracy"] = round((d["true_role"] == d["predicted_role"]).mean(), 2)
    rows.append(row)

df = pd.DataFrame(rows)
out = os.path.join(HERE, "results", "batch_summary.csv")
os.makedirs(os.path.dirname(out), exist_ok=True)
df.to_csv(out, index=False)
print(f"\n{'=' * 70}\nBATCH SUMMARY\n{'=' * 70}")
print(df.to_string(index=False))
print(f"\nSaved {out}")
print("Empty evaluation columns = no ground truth yet (see the *_TEMPLATE.csv files in the ground_truth folder).")
