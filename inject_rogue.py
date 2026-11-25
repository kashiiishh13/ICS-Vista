# inject_rogue.py
# Creates a COPY of a Modbus capture with simulated attacker traffic added near the end,
# so you can check that alerts.py raises the right alerts (true positives).
#
# Usage:
#   python inject_rogue.py "C:\path\Modbus_polling_only_6RTU.pcap"
#   python inject_rogue.py "C:\path\Modbus_polling_only_6RTU.pcap" --scenario new_device
#   python inject_rogue.py "C:\path\mb.pcap" --scenario spoof --out test_spoof.pcap
#
# Scenarios:
#   new_device  an unknown IP sends Modbus reads then writes to a controller (rogue device)
#   spoof       a KNOWN client IP sends writes, but from a different MAC address (impersonation)
#   both        (default) both attacks, at different times
#
# The original file is never modified. Only the Python standard library is needed.
import argparse, collections, os, random, struct, sys

# ---------------------------------------------------------------- pcap / pcapng reading
def read_pcap(path):
    """Return a list of (timestamp_seconds, frame_bytes). Supports classic pcap and pcapng (Ethernet)."""
    d = open(path, "rb").read()
    out = []
    magic = d[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        end = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        off = 24
        while off + 16 <= len(d):
            sec, frac, cl, _ = struct.unpack(end + "IIII", d[off:off + 16]); off += 16
            out.append((sec + frac / (1e9 if nano else 1e6), d[off:off + cl])); off += cl
        return out
    if magic == b"\x0a\x0d\x0d\x0a":
        end = "<" if d[8:12] == b"\x4d\x3c\x2b\x1a" else ">"
        off, resol = 0, []
        while off + 12 <= len(d):
            btype, blen = struct.unpack(end + "II", d[off:off + 8])
            body = d[off + 8:off + blen - 4]
            if btype == 1:                                   # interface description
                tsres, o = 1e-6, 8
                while o + 4 <= len(body):
                    code, ln = struct.unpack(end + "HH", body[o:o + 4])
                    if code == 0:
                        break
                    if code == 9 and ln >= 1:
                        v = body[o + 4]
                        tsres = 10.0 ** -(v & 0x7F) if not v & 0x80 else 2.0 ** -(v & 0x7F)
                    o += 4 + ((ln + 3) // 4) * 4
                resol.append(tsres)
            elif btype == 6:                                 # enhanced packet block
                ifid, th, tl, cl, _ = struct.unpack(end + "IIIII", body[:20])
                res = resol[ifid] if ifid < len(resol) else 1e-6
                out.append((((th << 32) | tl) * res, body[20:20 + cl]))
            off += blen
        return out
    sys.exit("Unrecognised capture format (expected pcap or pcapng).")


def write_pcap(path, packets):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in packets:
            sec = int(ts)
            f.write(struct.pack("<IIII", sec, int(round((ts - sec) * 1e6)), len(frame), len(frame)))
            f.write(frame)


# ---------------------------------------------------------------- packet building
def mac_b(m):
    return bytes(int(x, 16) for x in m.split(":"))

def ip_b(ip):
    return bytes(int(x) for x in ip.split("."))

def csum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def tcp_frame(src_mac, dst_mac, src_ip, dst_ip, sport, dport, payload, seq, ack, ident):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, 0x18, 8192, 0, 0) + payload
    pseudo = ip_b(src_ip) + ip_b(dst_ip) + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", csum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(tcp), ident, 0x4000, 64, 6, 0) + ip_b(src_ip) + ip_b(dst_ip)
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    return mac_b(dst_mac) + mac_b(src_mac) + b"\x08\x00" + ip + tcp

def modbus_req(tid, fc, addr, value):
    return struct.pack("!HHHBBHH", tid, 0, 6, 1, fc, addr, value)

def modbus_resp(tid, fc, req_value):
    if fc == 3:                                              # read holding registers: 1 register
        return struct.pack("!HHHBBBH", tid, 0, 5, 1, 3, 2, 1234)
    return struct.pack("!HHHBBHH", tid, 0, 6, 1, fc, 0, req_value)   # write echo


# ---------------------------------------------------------------- capture analysis
def parse(frame):
    """Minimal Ethernet/IPv4/TCP parse. Returns dict or None."""
    if len(frame) < 54 or frame[12:14] != b"\x08\x00" or frame[14] >> 4 != 4 or frame[23] != 6:
        return None
    ihl = (frame[14] & 15) * 4
    t = 14 + ihl
    if len(frame) < t + 20:
        return None
    doff = (frame[t + 12] >> 4) * 4
    return {"smac": ":".join("%02x" % b for b in frame[6:12]),
            "src": ".".join(str(b) for b in frame[26:30]), "dst": ".".join(str(b) for b in frame[30:34]),
            "sport": struct.unpack("!H", frame[t:t + 2])[0], "dport": struct.unpack("!H", frame[t + 2:t + 4])[0],
            "paylen": len(frame) - t - doff}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--scenario", choices=["new_device", "spoof", "both"], default="both")
    ap.add_argument("--out", default=None, help="output file (default: <name>_rogue.pcap next to the input)")
    ap.add_argument("--victim-ip", default=None, help="Modbus server to attack (default: most polled)")
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()
    random.seed(args.seed)

    packets = read_pcap(args.pcap)
    if not packets:
        sys.exit("No packets read.")
    t0, t1 = min(t for t, _ in packets), max(t for t, _ in packets)
    dur = t1 - t0

    ip_mac, pairs, all_ips = {}, collections.Counter(), set()
    for ts, fr in packets:
        p = parse(fr)
        if not p:
            continue
        all_ips.update([p["src"], p["dst"]])
        ip_mac.setdefault(p["src"], p["smac"])
        if p["dport"] == 502 and p["paylen"] > 0:
            pairs[(p["src"], p["dst"])] += 1
    if not pairs:
        sys.exit("This capture has no Modbus (port 502) requests. Use a Modbus capture, "
                 "for example Modbus_polling_only_6RTU.pcap or mb.pcap.")

    if args.victim_ip:
        cand = [(c, s) for (c, s) in pairs if s == args.victim_ip]
        if not cand:
            sys.exit(f"No Modbus requests to {args.victim_ip} found.")
        client, victim = max(cand, key=lambda k: pairs[k])
    else:
        client, victim = max(pairs, key=lambda k: pairs[k])
    victim_mac = ip_mac.get(victim)
    if not victim_mac:
        sys.exit("Could not learn the victim's MAC address.")

    new = []
    notes = []

    def window(a, b):
        return t0 + dur * a, t0 + dur * b

    def add_session(src_ip, src_mac, steps, start, end, label):
        sport = random.randint(49200, 65000)
        seq_c, seq_s = random.randint(1000, 10 ** 6), random.randint(1000, 10 ** 6)
        gap = (end - start) / max(len(steps), 1)
        for i, (fc, addr, val) in enumerate(steps):
            ts = start + i * gap
            req = modbus_req(i + 1, fc, addr, val)
            rsp = modbus_resp(i + 1, fc, val)
            new.append((ts, tcp_frame(src_mac, victim_mac, src_ip, victim, sport, 502, req, seq_c, seq_s, 1000 + i)))
            new.append((ts + 0.002, tcp_frame(victim_mac, src_mac, victim, src_ip, 502, sport, rsp, seq_s, seq_c + len(req), 2000 + i)))
            seq_c += len(req); seq_s += len(rsp)
        notes.append(f"{label}: {len(steps)} requests from +{(start - t0) / 60:.1f} to +{(end - t0) / 60:.1f} min")

    if args.scenario in ("new_device", "both"):
        prefix = victim.rsplit(".", 1)[0]
        rogue_ip = next(f"{prefix}.{n}" for n in range(200, 255) if f"{prefix}.{n}" not in all_ips)
        rogue_mac = "02:de:ad:00:00:01"
        steps = [(3, 0, 1)] * 5 + [(6, 10 + i % 5, 9999) for i in range(25)]    # recon reads, then writes
        s, e = window(0.85, 0.88)
        add_session(rogue_ip, rogue_mac, steps, s, e, f"NEW_DEVICE {rogue_ip} (MAC {rogue_mac}) -> {victim}:502")

    if args.scenario in ("spoof", "both"):
        spoof_mac = "02:de:ad:00:00:02"
        steps = [(6, 20 + i, 4242) for i in range(10)]
        s, e = window(0.92, 0.94)
        add_session(client, spoof_mac, steps, s, e,
                    f"MAC_CHANGE {client} (real MAC {ip_mac.get(client)}) now from MAC {spoof_mac} -> {victim}:502")

    merged = sorted(packets + new, key=lambda x: x[0])
    out = args.out or os.path.splitext(args.pcap)[0] + "_rogue.pcap"
    write_pcap(out, merged)
    print(f"Base capture : {len(packets)} packets, {dur / 60:.1f} min, victim server {victim}, known client {client}")
    print(f"Injected     : {len(new)} packets")
    for n in notes:
        print("  -", n)
    print(f"Saved        : {out}")
    print("\nNow run:  python alerts.py \"" + out + "\"")


if __name__ == "__main__":
    main()
