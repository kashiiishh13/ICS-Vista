# scalability.py
# Usage: python scalability.py 4SICS-GeekLounge-151020.pcap
# Requires the LIMIT edit in ics_vista2.py (second argument = max packets, 0 = all).
# NOTE: each run overwrites inventory.csv/graph.png; the last run is the full capture,
# so your final files are the complete results.
import re, subprocess, sys
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

if len(sys.argv) < 2:
    print("Usage: python scalability.py <file.pcap>")
    sys.exit(1)

pcap = sys.argv[1]
limits = [25000, 50000, 100000, 150000, 200000, 0]   # 0 = whole file (keep last)
pattern = re.compile(r"Packets read:\s*(\d+)\s*\|\s*Time:\s*([\d.]+)s")

rows = []
for lim in limits:
    print(f"Running with limit {lim or 'ALL'} ...", flush=True)
    out = subprocess.run([sys.executable, "ics_vista2.py", pcap, str(lim)],
                         capture_output=True, text=True).stdout
    m = pattern.search(out)
    if not m:
        print("  could not parse output, skipping")
        continue
    pk, sec = int(m.group(1)), float(m.group(2))
    rows.append({"packets": pk, "seconds": round(sec, 1),
                 "packets_per_sec": round(pk / sec)})
    print(f"  {pk} packets in {sec:.1f}s ({pk / sec:.0f} pkt/s)")

df = pd.DataFrame(rows).drop_duplicates("packets")
df.to_csv("scaling.csv", index=False)
print("\n", df.to_string(index=False))

fig, ax = plt.subplots(1, 2, figsize=(10, 4))
ax[0].plot(df["packets"], df["seconds"], marker="o")
ax[0].set_xlabel("Packets processed"); ax[0].set_ylabel("Time (s)")
ax[0].set_title("Processing time vs. traffic volume")
ax[1].plot(df["packets"], df["packets_per_sec"], marker="o", color="tab:green")
ax[1].set_xlabel("Packets processed"); ax[1].set_ylabel("Packets / second")
ax[1].set_title("Throughput")
ax[1].set_ylim(bottom=0)
plt.tight_layout()
plt.savefig("scaling.png", dpi=150)
print("Saved scaling.csv and scaling.png")