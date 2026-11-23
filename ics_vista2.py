# ics_vista2.py
# Usage: python ics_vista2.py 4SICS-GeekLounge-151020.pcap
import sys, time, warnings
warnings.filterwarnings("ignore")
from collections import defaultdict
from statistics import mean, pstdev
from scapy.all import PcapReader, IP, TCP, Ether
import pandas as pd

# ---------------- settings you can tune ----------------
PORTS = {502: "Modbus", 20000: "DNP3", 102: "S7comm",
         44818: "EtherNet/IP", 4840: "OPC UA"}

SERVER_RATIO_MIN = 0.80   # share of ICS payload packets sent as server -> field controller
CV_STEADY_MAX = 0.50      # timing CV below this = steady polling (HMI-like)
# -------------------------------------------------------

# Function codes that indicate engineering activity (write / download / upload / control)
S7_ENG = {0x05, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x28, 0x29}
S7_READ = {0x04}
MODBUS_WRITE = {5, 6, 15, 16, 22, 23}
MODBUS_READ = {1, 2, 3, 4}


def parse_s7_function(payload):
    """Return S7 function code of a Job request, else None.
    Layout: TPKT(4) + COTP(LI+1) + S7 header(10 or 12) + parameter (1st byte = function)."""
    if len(payload) < 17 or payload[0] != 0x03:
        return None
    cotp_len = payload[4] + 1
    s7 = 5 + cotp_len - 1  # TPKT is 4 bytes, COTP starts at index 4
    s7 = 4 + cotp_len
    if len(payload) <= s7 + 10 or payload[s7] != 0x32:
        return None
    rosctr = payload[s7 + 1]
    if rosctr != 1:          # only Job requests carry the function we care about
        return None
    return payload[s7 + 10]


def parse_modbus_function(payload):
    """MBAP header is 7 bytes, function code is byte 8."""
    if len(payload) < 8:
        return None
    return payload[7] & 0x7F


def new_device():
    return {"macs": set(), "protocols": set(), "peers": set(),
            "as_client": 0, "as_server": 0,
            "reads": 0, "writes": 0, "times": []}


devices = defaultdict(new_device)

if len(sys.argv) < 2:
    print("Usage: python ics_vista2.py <file.pcap>")
    sys.exit(1)

start = time.time()
n_packets = 0

with PcapReader(sys.argv[1]) as reader:
    for pkt in reader:
        n_packets += 1
        if IP not in pkt or TCP not in pkt:
            continue
        src, dst = pkt[IP].src, pkt[IP].dst
        if src.startswith("127.") or dst.startswith("127."):
            continue

        payload = bytes(pkt[TCP].payload)
        if len(payload) == 0:          # ignore empty ACKs
            continue

        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        if dport in PORTS:             # src is client sending a request
            proto, client, server, is_request = PORTS[dport], src, dst, True
        elif sport in PORTS:           # src is server sending a response
            proto, client, server, is_request = PORTS[sport], dst, src, False
        else:
            continue

        if Ether in pkt:
            devices[src]["macs"].add(pkt[Ether].src)

        c, s = devices[client], devices[server]
        c["protocols"].add(proto); s["protocols"].add(proto)
        c["peers"].add(server);    s["peers"].add(client)

        if is_request:
            c["as_client"] += 1
            c["times"].append(float(pkt.time))
            fc = None
            if proto == "S7comm":
                fc = parse_s7_function(payload)
                if fc in S7_ENG:   c["writes"] += 1
                elif fc in S7_READ: c["reads"] += 1
            elif proto == "Modbus":
                fc = parse_modbus_function(payload)
                if fc in MODBUS_WRITE: c["writes"] += 1
                elif fc in MODBUS_READ: c["reads"] += 1
        else:
            s["as_server"] += 1

elapsed = time.time() - start


def timing_cv(times):
    """Coefficient of variation of gaps between requests. Low = steady/periodic."""
    if len(times) < 10:
        return None
    gaps = [b - a for a, b in zip(times, times[1:]) if b > a]
    if len(gaps) < 5 or mean(gaps) == 0:
        return None
    return pstdev(gaps) / mean(gaps)


WRITE_SHARE_ENG = 0.05   # if >=5% of read/write requests are writes/eng -> engineering

def classify(d, cv):
    total = d["as_client"] + d["as_server"]
    if total == 0:
        return "unknown"
    if d["as_server"] / total >= SERVER_RATIO_MIN:
        return "field_controller"
    rw = d["reads"] + d["writes"]
    if rw == 0:
        return "unknown"
    write_share = d["writes"] / rw
    if write_share >= WRITE_SHARE_ENG:
        return "engineering_workstation"
    return "supervisory"


rows = []
for ip, d in devices.items():
    cv = timing_cv(d["times"])
    rows.append({
        "ip": ip,
        "mac": ",".join(sorted(d["macs"])),
        "protocols": ",".join(sorted(d["protocols"])),
        "client_pkts": d["as_client"],
        "server_pkts": d["as_server"],
        "peers": len(d["peers"]),
        "reads": d["reads"],
        "writes_or_eng": d["writes"],
        "write_share": round(d["writes"] / (d["reads"] + d["writes"]), 4) if (d["reads"] + d["writes"]) else "",
        "timing_cv": round(cv, 3) if cv is not None else "",
        "predicted_role": classify(d, cv),
    })

df = pd.DataFrame(rows).sort_values("ip")
df.to_csv("inventory.csv", index=False)
print(df.to_string(index=False))
print(f"\nPackets read: {n_packets}  |  Time: {elapsed:.1f}s  |  "
      f"Speed: {n_packets / max(elapsed, 1e-9):.0f} packets/s")
print("Saved inventory.csv")

# ---------- optional: communication graph ----------
try:
    import networkx as nx
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    G = nx.DiGraph()
    colors = {"field_controller": "tab:green", "supervisory": "tab:blue",
              "engineering_workstation": "tab:orange", "unknown": "tab:gray"}
    role_of = dict(zip(df["ip"], df["predicted_role"]))
    for ip, d in devices.items():
        G.add_node(ip)
        for peer in d["peers"]:
            if d["as_client"] > 0 and (peer in devices):
                G.add_edge(ip, peer)
    node_colors = [colors.get(role_of.get(n, "unknown"), "tab:gray") for n in G.nodes]
    plt.figure(figsize=(7, 5))
    nx.draw(G, with_labels=True, node_color=node_colors, node_size=1800, font_size=8, arrows=True)
    plt.title("ICS-Vista communication graph")
    plt.savefig("graph.png", dpi=150, bbox_inches="tight")
    print("Saved graph.png")
except Exception as e:
    print("Graph skipped:", e)