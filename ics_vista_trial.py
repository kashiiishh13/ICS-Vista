# ics_vista_day1.py
# Usage: python ics_vista_day1.py capture.pcap
import sys
from collections import defaultdict
from scapy.all import rdpcap, IP, TCP

PORTS = {502: "Modbus", 20000: "DNP3", 102: "S7comm",
         44818: "EtherNet/IP", 4840: "OPC UA"}

devices = defaultdict(lambda: {
    "mac": set(), "protocols": set(),
    "as_client": 0, "as_server": 0, "peers": set()
})

for pkt in rdpcap(sys.argv[1]):
    if IP not in pkt or TCP not in pkt:
        continue
    src, dst = pkt[IP].src, pkt[IP].dst
    sport, dport = pkt[TCP].sport, pkt[TCP].dport

    if dport in PORTS:          # src is client, dst is server
        proto = PORTS[dport]
        client, server = src, dst
    elif sport in PORTS:        # src is server replying
        proto = PORTS[sport]
        client, server = dst, src
    else:
        continue

    devices[client]["as_client"] += 1
    devices[client]["protocols"].add(proto)
    devices[client]["peers"].add(server)
    devices[server]["as_server"] += 1
    devices[server]["protocols"].add(proto)
    devices[server]["peers"].add(client)
    if src in (client, server) and pkt.haslayer("Ether"):
        devices[src]["mac"].add(pkt["Ether"].src)

print(f"{'IP':16} {'Protocols':22} {'Client':>7} {'Server':>7} {'Peers':>6}")
for ip, d in devices.items():
    print(f"{ip:16} {','.join(sorted(d['protocols'])):22} "
          f"{d['as_client']:>7} {d['as_server']:>7} {len(d['peers']):>6}")