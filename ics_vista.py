# ics_vista.py
# Usage: python ics_vista.py capture.pcap [max_packets]
# Needs ics_decoders.py in the same folder.
import sys, time, warnings
warnings.filterwarnings("ignore")
from collections import defaultdict
from statistics import mean, pstdev
from scapy.all import PcapReader, IP, TCP, UDP, Ether
import pandas as pd
from ics_decoders import PORTS, request_kind, flow_direction, looks_like, classify_role

# Role thresholds (SERVER_RATIO_MIN, WRITE_SHARE_ENG, FANOUT_SUPERVISORY_MIN) live in ics_decoders.py

LIMIT = int(sys.argv[2]) if len(sys.argv) > 2 and int(sys.argv[2]) > 0 else None


def new_device():
    return {"macs": set(), "protocols": set(), "peers": set(),
            "as_client": 0, "as_server": 0,
            "reads": 0, "writes": 0, "times": []}


devices = defaultdict(new_device)

if len(sys.argv) < 2:
    print("Usage: python ics_vista.py <file.pcap> [max_packets]")
    sys.exit(1)

start = time.time()
n_packets = 0

with PcapReader(sys.argv[1]) as reader:
    for pkt in reader:
        if LIMIT and n_packets >= LIMIT:
            break
        n_packets += 1
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
        if len(payload) == 0:          # ignore empty ACKs
            continue

        flow = flow_direction(l4.sport, l4.dport)
        if flow is None:
            continue
        proto, is_request = flow
        if is_udp and not looks_like(proto, payload):   # e.g. DNS with an unlucky port
            continue
        client, server = (src, dst) if is_request else (dst, src)

        if Ether in pkt:
            devices[src]["macs"].add(pkt[Ether].src)

        c, s = devices[client], devices[server]
        c["protocols"].add(proto); s["protocols"].add(proto)
        c["peers"].add(server);    s["peers"].add(client)

        if is_request:
            c["as_client"] += 1
            c["times"].append(float(pkt.time))
            kind = request_kind(proto, payload)
            if kind == "write":
                c["writes"] += 1
            elif kind == "read":
                c["reads"] += 1
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


def classify(d):
    return classify_role(d["as_client"], d["as_server"], d["reads"], d["writes"], len(d["peers"]))


rows = []
for ip, d in devices.items():
    cv = timing_cv(d["times"])
    rw = d["reads"] + d["writes"]
    rows.append({
        "ip": ip,
        "mac": ",".join(sorted(d["macs"])),
        "protocols": ",".join(sorted(d["protocols"])),
        "client_pkts": d["as_client"],
        "server_pkts": d["as_server"],
        "peers": len(d["peers"]),
        "reads": d["reads"],
        "writes_or_eng": d["writes"],
        "write_share": round(d["writes"] / rw, 4) if rw else "",
        "decode_coverage": round(rw / d["as_client"], 2) if d["as_client"] else "",
        "timing_cv": round(cv, 3) if cv is not None else "",
        "predicted_role": classify(d),
    })

COLUMNS = ["ip", "mac", "protocols", "client_pkts", "server_pkts", "peers", "reads",
           "writes_or_eng", "write_share", "decode_coverage", "timing_cv", "predicted_role"]
df = pd.DataFrame(rows, columns=COLUMNS)
if len(df):
    df = df.sort_values("ip")
df.to_csv("inventory.csv", index=False)
if len(df):
    print(df.to_string(index=False))
else:
    print("No ICS devices found: no payload traffic on the supported protocols "
          "(Modbus 502, DNP3 20000, S7comm 102, EtherNet/IP 44818/2222, OPC UA 4840, HART-IP 5094/5095).")
print(f"\nPackets read: {n_packets}  |  Time: {elapsed:.1f}s  |  "
      f"Speed: {n_packets / max(elapsed, 1e-9):.0f} packets/s")
print("Saved inventory.csv")

# ---------- optional: communication graph ----------
try:
    if len(df) == 0:
        raise ValueError("no devices to draw")
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
        if d["as_client"] > 0:
            for peer in d["peers"]:
                if peer in devices:
                    G.add_edge(ip, peer)
    node_colors = [colors.get(role_of.get(n, "unknown"), "tab:gray") for n in G.nodes]
    plt.figure(figsize=(7, 5))
    nx.draw(G, with_labels=True, node_color=node_colors, node_size=1800, font_size=8, arrows=True)
    plt.title("ICS-Vista communication graph")
    plt.savefig("graph.png", dpi=150, bbox_inches="tight")
    print("Saved graph.png")
except Exception as e:
    print("Graph skipped:", e)
