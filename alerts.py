# alerts.py
# Usage: python alerts.py 4SICS-GeekLounge-151020.pcap
# Learns devices/roles from the first part of the capture, then raises alerts
# for new devices or role changes in the rest. On a static network, every alert is a false alert.
import sys, warnings
warnings.filterwarnings("ignore")
from collections import defaultdict
from scapy.all import PcapReader, IP, TCP

PORTS = {502: "Modbus", 20000: "DNP3", 102: "S7comm",
         44818: "EtherNet/IP", 4840: "OPC UA"}
S7_ENG = {0x05, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x28, 0x29}
S7_READ = {0x04}
MODBUS_WRITE = {5, 6, 15, 16, 22, 23}
MODBUS_READ = {1, 2, 3, 4}

SERVER_RATIO_MIN = 0.80
WRITE_SHARE_ENG = 0.05
MIN_EVIDENCE = 5          # minimum packets / read+write requests before giving a role
LEARN_FRACTION = 0.20     # first 20% of capture time = learning window
STEP = 0.10               # check every 10% of capture time afterwards


def s7_function(p):
    if len(p) < 17 or p[0] != 0x03:
        return None
    s7 = 4 + p[4] + 1
    if len(p) <= s7 + 10 or p[s7] != 0x32 or p[s7 + 1] != 1:
        return None
    return p[s7 + 10]


def modbus_function(p):
    return (p[7] & 0x7F) if len(p) >= 8 else None


# ---------- pass 1: read pcap into a compact event list ----------
if len(sys.argv) < 2:
    print("Usage: python alerts.py <file.pcap>")
    sys.exit(1)

events = []   # (time, client, server, kind, is_request)
with PcapReader(sys.argv[1]) as reader:
    for pkt in reader:
        if IP not in pkt or TCP not in pkt:
            continue
        src, dst = pkt[IP].src, pkt[IP].dst
        if src.startswith("127.") or dst.startswith("127."):
            continue
        payload = bytes(pkt[TCP].payload)
        if not payload:
            continue
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        if dport in PORTS:
            proto, client, server, is_req = PORTS[dport], src, dst, True
        elif sport in PORTS:
            proto, client, server, is_req = PORTS[sport], dst, src, False
        else:
            continue
        kind = None
        if is_req:
            if proto == "S7comm":
                fc = s7_function(payload)
                kind = "write" if fc in S7_ENG else "read" if fc in S7_READ else None
            elif proto == "Modbus":
                fc = modbus_function(payload)
                kind = "write" if fc in MODBUS_WRITE else "read" if fc in MODBUS_READ else None
        events.append((float(pkt.time), client, server, kind, is_req))

if not events:
    print("No ICS traffic found.")
    sys.exit(0)

events.sort(key=lambda e: e[0])
t0, t1 = events[0][0], events[-1][0]
dur = t1 - t0
print(f"ICS events: {len(events)}  |  capture duration: {dur / 3600:.2f} h")


# ---------- classifier (same rules as ics_vista2.py) ----------
def role(d):
    total = d["c"] + d["s"]
    if total < MIN_EVIDENCE:
        return "unknown"
    if d["s"] / total >= SERVER_RATIO_MIN:
        return "field_controller"
    rw = d["r"] + d["w"]
    if rw < MIN_EVIDENCE:
        return "unknown"
    return "engineering_workstation" if d["w"] / rw >= WRITE_SHARE_ENG else "supervisory"


# ---------- pass 2: learning window, then checkpoints ----------
n_steps = int(round((1 - LEARN_FRACTION) / STEP))
checkpoints = [t0 + dur * (LEARN_FRACTION + i * STEP) for i in range(n_steps + 1)]
state = defaultdict(lambda: {"c": 0, "s": 0, "r": 0, "w": 0})
baseline_devices, baseline_roles, alerts = set(), {}, []
idx = 0

for ci, cp in enumerate(checkpoints):
    while idx < len(events) and events[idx][0] <= cp:
        _, client, server, kind, is_req = events[idx]
        _ = state[client], state[server]            # make sure both devices exist
        if is_req:
            state[client]["c"] += 1
            if kind == "read":
                state[client]["r"] += 1
            elif kind == "write":
                state[client]["w"] += 1
        else:
            state[server]["s"] += 1
        idx += 1

    roles_now = {ip: role(d) for ip, d in state.items()}

    if ci == 0:                                      # end of learning window
        baseline_devices = set(state)
        baseline_roles = dict(roles_now)
        print(f"Learned {len(baseline_devices)} devices: {sorted(baseline_devices)}")
        for ip, r in sorted(baseline_roles.items()):
            print(f"  {ip}: {r}")
        continue

    for ip, r in roles_now.items():
        if ip not in baseline_devices:
            alerts.append((cp - t0, "NEW_DEVICE", ip, r))
            baseline_devices.add(ip)
            baseline_roles[ip] = r
        else:
            prev = baseline_roles.get(ip, "unknown")
            if prev == "unknown":
                baseline_roles[ip] = r               # first real evidence, not an alert
            elif r != "unknown" and r != prev:
                alerts.append((cp - t0, "ROLE_CHANGE", ip, f"{prev} -> {r}"))
                baseline_roles[ip] = r

monitored_h = dur * (1 - LEARN_FRACTION) / 3600
print("\n=== Alerts after learning window ===")
if not alerts:
    print("None")
for t, kind, ip, info in alerts:
    print(f"t={t / 60:7.1f} min  {kind:12} {ip}  {info}")
print(f"\nTotal alerts: {len(alerts)}  |  monitored: {monitored_h:.2f} h  |  "
      f"alerts/hour: {len(alerts) / monitored_h if monitored_h else 0:.2f}")