# run_all.py
# Usage:
#   python run_all.py "C:\path\to\capture.pcap"
#   python run_all.py "C:\path\to\capture.pcap" --ground-truth gt_modbus.csv
#   python run_all.py "C:\path\to\capture.pcap" --skip-scalability
#
# Runs: ics_vista.py -> evaluate.py -> alerts.py -> scalability.py
# Results go to results/<pcap name>/ so different datasets never overwrite each other.
# Keep this file in the same folder as ics_vista.py, ics_decoders.py, evaluate.py,
# alerts.py and scalability.py.
import argparse, os, shutil, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))

parser = argparse.ArgumentParser()
parser.add_argument("pcap", help="path to the .pcap file")
parser.add_argument("--ground-truth", default=None,
                    help="ground truth CSV (ip,true_role). Default: ground_truth/<pcap name>.csv")
parser.add_argument("--skip-scalability", action="store_true",
                    help="skip the slow scalability test")
parser.add_argument("--force-scalability", action="store_true",
                    help="run the scalability test even on small captures")
args = parser.parse_args()

pcap = os.path.abspath(args.pcap)
if not os.path.exists(pcap):
    sys.exit(f"PCAP not found: {pcap}")

for needed in ["ics_vista.py", "ics_decoders.py", "evaluate.py", "alerts.py", "scalability.py"]:
    if not os.path.exists(os.path.join(HERE, needed)):
        sys.exit(f"Missing {needed} in {HERE}")

name = os.path.splitext(os.path.basename(pcap))[0]
outdir = os.path.join(HERE, "results", name)
os.makedirs(outdir, exist_ok=True)

gt_src = args.ground_truth
if gt_src is None:
    # default: look for ground_truth/<pcap name>.csv, then ground_truth_<pcap name>.csv
    candidates = [os.path.join(HERE, "ground_truth", name + ".csv"),
                  os.path.join(HERE, f"ground_truth_{name}.csv"),
                  os.path.join(HERE, "ground_truth.csv")]
    gt_src = next((c for c in candidates if os.path.exists(c)), candidates[0])
elif not os.path.isabs(gt_src):
    gt_src = os.path.join(HERE, gt_src)
have_gt = os.path.exists(gt_src)
if have_gt:
    shutil.copy(gt_src, os.path.join(outdir, "ground_truth.csv"))

log_path = os.path.join(outdir, "run_log.txt")
log = open(log_path, "w", encoding="utf-8")


def run(title, script, extra_args):
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}", flush=True)
    log.write(f"\n{'=' * 70}\n{title}\n{'=' * 70}\n")
    t = time.time()
    proc = subprocess.Popen([sys.executable, os.path.join(HERE, script)] + extra_args,
                            cwd=outdir, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, encoding="utf-8", errors="replace")
    for line in proc.stdout:
        if "CryptographyDeprecationWarning" in line or "cipher=algorithms" in line:
            continue
        print(line, end="", flush=True)
        log.write(line)
    proc.wait()
    ok = proc.returncode == 0
    secs = time.time() - t
    status = "OK" if ok else f"FAILED (exit code {proc.returncode})"
    print(f"\n[{title}] {status} in {secs:.0f}s", flush=True)
    log.write(f"\n[{title}] {status} in {secs:.0f}s\n")
    return ok


results = {}
results["1. Discovery + roles"] = run("STEP 1: Discovery and role classification", "ics_vista.py", [pcap])

if have_gt and results["1. Discovery + roles"]:
    results["2. Evaluation"] = run("STEP 2: Evaluation against ground truth", "evaluate.py", [])
else:
    reason = "no ground truth file found" if not have_gt else "step 1 failed"
    print(f"\nSkipping evaluation: {reason} (looked for {gt_src})")
    results["2. Evaluation"] = None
    inv_path = os.path.join(outdir, "inventory.csv")
    if not have_gt and results["1. Discovery + roles"] and os.path.exists(inv_path):
        import csv
        gt_dir = os.path.join(HERE, "ground_truth")
        os.makedirs(gt_dir, exist_ok=True)
        tpl_path = os.path.join(gt_dir, name + "_TEMPLATE.csv")
        with open(inv_path, newline="", encoding="utf-8") as f_in, \
                open(tpl_path, "w", newline="", encoding="utf-8") as f_out:
            w = csv.writer(f_out)
            w.writerow(["ip", "true_role"])
            for row in csv.DictReader(f_in):
                w.writerow([row["ip"], ""])
        print(f"\nCreated a ground-truth TEMPLATE: {tpl_path}")
        print("  Fill the true_role column from Wireshark (NOT from the tool's predictions),")
        print("  add any ICS device the tool missed, then rename it to:")
        print(f"  {os.path.join(gt_dir, name + '.csv')}")
        print("  Roles: field_controller, supervisory, engineering_workstation")

results["3. False alerts"] = run("STEP 3: False-alert test", "alerts.py", [pcap])

SMALL_FILE_BYTES = 5 * 1024 * 1024
if args.skip_scalability:
    print("\nSkipping scalability test (--skip-scalability).")
    results["4. Scalability"] = None
elif os.path.getsize(pcap) < SMALL_FILE_BYTES and not args.force_scalability:
    print(f"\nSkipping scalability test: capture is under 5 MB, too small to measure. "
          f"Use --force-scalability to run it anyway.")
    results["4. Scalability"] = None
else:
    results["4. Scalability"] = run("STEP 4: Scalability test", "scalability.py", [pcap])

print(f"\n{'=' * 70}\nSUMMARY\n{'=' * 70}")
for step, ok in results.items():
    print(f"  {step:25} {'skipped' if ok is None else 'OK' if ok else 'FAILED'}")
print(f"\nAll outputs saved in: {outdir}")
print("  inventory.csv, graph.png, evaluation_results.csv, scaling.csv, scaling.png, run_log.txt")
log.close()
