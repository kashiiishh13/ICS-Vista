# test_decoders.py
# Usage: python test_decoders.py capture.pcap
# 1) Port census: which TCP/UDP service ports carry data, and which are NOT decoded.
# 2) Decoder check: how many requests per protocol were understood as read / write / other.
# Does NOT skip loopback, so it also works on single-host sample captures like dnp3_read.pcap.
import sys, warnings
warnings.filterwarnings("ignore")
from collections import Counter
from scapy.all import PcapReader, TCP, UDP
from ics_decoders import PORTS, request_kind, flow_direction

if len(sys.argv) < 2:
    print("Usage: python test_decoders.py <file.pcap>")
    sys.exit(1)

census = Counter()
kinds = Counter()

with PcapReader(sys.argv[1]) as reader:
    for pkt in reader:
        if TCP in pkt:
            l4, transport = pkt[TCP], "TCP"
        elif UDP in pkt:
            l4, transport = pkt[UDP], "UDP"
        else:
            continue
        payload = bytes(l4.payload)
        if not payload:
            continue
        census[(transport, min(l4.sport, l4.dport))] += 1   # lower port = likely the service
        flow = flow_direction(l4.sport, l4.dport)
        if flow and flow[1]:
            proto = flow[0]
            kinds[(proto, request_kind(proto, payload) or "other")] += 1

print("=== Port census (top 15 service ports with data) ===")
for (transport, port), n in census.most_common(15):
    status = f"decoded as {PORTS[port]}" if port in PORTS else "not an ICS port in our list"
    print(f"{transport} {port:>6}: {n:>8} packets   {status}")

print("\n=== Requests understood by the decoders ===")
if not kinds:
    print("No requests found on known ICS ports.")
for (proto, kind), n in sorted(kinds.items()):
    print(f"{proto:12} {kind:6} {n:>8}")
print("\n'other' = requests whose function code is not read/write (e.g. setup, keep-alive) or could not be parsed.")
