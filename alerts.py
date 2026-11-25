# alerts.py
# Usage: python alerts.py capture.pcap
# Learns devices, MAC addresses and roles from the first part of the capture, then raises alerts in the rest:
#   NEW_DEVICE   an IP that was not seen during learning starts speaking an ICS protocol (exact time)
#   MAC_CHANGE   a known IP is suddenly seen with a different MAC address (possible spoofing, exact time)
#   ROLE_CHANGE  a known device's role changes (checked every 10% of the capture)
# On a static network, every alert on a clean capture counts as a false alert.
import sys, warnings
warnings.filterwarnings("ignore")
from collections import defaultdict
from scapy.all import PcapReader, IP, TCP, UDP, Ether
from ics_decoders import PORTS, request_kind, flow_direction, looks_like, classify_role

MIN_EVIDENCE = 5          # minimum packets / read+write requests before giving a role
LEARN_FRACTION = 0.20     # first 20% of capture time = learning window
STEP = 0.10               # role checks every 10% of capture time afterwards


# ---------- pass 1: read pcap into a compact event list ----------
if len(sys.argv) < 2:
    print("Usage: python alerts.py <file.pcap>")
    sys.exit(1)

events = []   # (time, client, server, kind, is_request, src_ip, src_mac)
with PcapReader(sys.argv[1]) as reader:
    for pkt in reader:
        if IP not in pkt:
            continue
        src, dst = pkt[IP].src, pkt[IP].dst
        if src.startswith("127.") or dst.startswith("127."):
            continue
        if TCP in pkt:
            l4, is_udp = pkt[TCP], False
        elif UDP in pkt:
            l4, is_udp = pkt[UDP], True
        else:
            continue
        payload = bytes(l4.payload)
        if not payload:
            continue
        flow = flow_direction(l4.sport, l4.dport)
        if flow is None:
            continue
        proto, is_req = flow
        if is_udp and not looks_like(proto, payload):   # e.g. DNS with an unlucky port
            continue
        client, server = (src, dst) if is_req else (dst, src)
        kind = request_kind(proto, payload) if is_req else None
        mac = pkt[Ether].src.lower() if Ether in pkt else None
        events.append((float(pkt.time), client, server, kind, is_req, src, mac))

if not events:
    print("No ICS traffic found.")
    sys.exit(0)

events.sort(key=lambda e: e[0])
t0, t1 = events[0][0], events[-1][0]
dur = t1 - t0
learn_end = t0 + dur * LEARN_FRACTION
n_steps = int(round((1 - LEARN_FRACTION) / STEP))
checkpoints = [learn_end + dur * STEP * i for i in range(1, n_steps + 1)]
checkpoints[-1] = float("inf")                        # last check covers the end of the capture
print(f"ICS events: {len(events)}  |  capture duration: {dur / 3600:.2f} h")


# ---------- state ----------
def role(d):
    return classify_role(d["c"], d["s"], d["r"], d["w"], len(d["p"]), MIN_EVIDENCE)


state = defaultdict(lambda: {"c": 0, "s": 0, "r": 0, "w": 0, "p": set()})
macs_seen = defaultdict(set)
baseline_devices, baseline_roles, baseline_macs = None, {}, {}
alerts = []
next_cp = 0


def snapshot():
    """End of the learning window: remember devices, MACs and roles."""
    global baseline_devices, baseline_roles, baseline_macs
    baseline_devices = set(state)
    baseline_roles = {ip: role(d) for ip, d in state.items()}
    baseline_macs = {ip: set(m) for ip, m in macs_seen.items()}
    print(f"Learned {len(baseline_devices)} devices: {sorted(baseline_devices)}")
    for ip, r in sorted(baseline_roles.items()):
        macs = ",".join(sorted(baseline_macs.get(ip, [])))
        print(f"  {ip}: {r}  ({macs})")


def role_check(when):
    for ip, d in state.items():
        r = role(d)
        prev = baseline_roles.get(ip, "unknown")
        if prev == "unknown":
            baseline_roles[ip] = r                    # first real evidence, not an alert
        elif r != "unknown" and r != prev:
            alerts.append((when - t0, "ROLE_CHANGE", ip, f"{prev} -> {r}"))
            baseline_roles[ip] = r


def event_checks(ev):
    t, client, server, _, _, src, mac = ev
    for ip in (client, server):
        if ip not in baseline_devices:
            alerts.append((t - t0, "NEW_DEVICE", ip, "first seen after learning window"))
            baseline_devices.add(ip)
    if mac:
        if src in baseline_macs:
            if mac not in baseline_macs[src]:
                known = ",".join(sorted(baseline_macs[src]))
                alerts.append((t - t0, "MAC_CHANGE", src, f"known MAC {known} -> now {mac}"))
                baseline_macs[src].add(mac)
        else:
            baseline_macs[src] = {mac}               # new device: its MAC is noted silently


def apply(ev):
    _, client, server, kind, is_req, src, mac = ev
    _ = state[client], state[server]                  # make sure both devices exist
    state[client]["p"].add(server)
    state[server]["p"].add(client)
    if mac:
        macs_seen[src].add(mac)
    if is_req:
        state[client]["c"] += 1
        if kind == "read":
            state[client]["r"] += 1
        elif kind == "write":
            state[client]["w"] += 1
    else:
        state[server]["s"] += 1


# ---------- pass 2: learn, then monitor ----------
for ev in events:
    t = ev[0]
    if baseline_devices is None and t > learn_end:
        snapshot()
    if baseline_devices is not None:
        while next_cp < len(checkpoints) and t > checkpoints[next_cp]:
            role_check(checkpoints[next_cp])
            next_cp += 1
        event_checks(ev)
    apply(ev)

if baseline_devices is None:                         # capture ended inside the learning window
    snapshot()
while next_cp < len(checkpoints):
    role_check(t1)
    next_cp += 1

monitored_h = dur * (1 - LEARN_FRACTION) / 3600
print("\n=== Alerts after learning window ===")
if not alerts:
    print("None")
for t, kind, ip, info in sorted(alerts):
    print(f"t=+{t / 60:7.1f} min  {kind:12} {ip}  {info}")
print(f"\nTotal alerts: {len(alerts)}  |  monitored: {monitored_h:.2f} h  |  "
      f"alerts/hour: {len(alerts) / monitored_h if monitored_h else 0:.2f}")
