# ics_decoders.py
# Header-level decoders. Each function looks at the application payload of a REQUEST
# (client -> server) and returns "read", "write" or None (unknown / not decodable).
# "write" means write, control, download or other engineering-type activity.

PORTS = {502: "Modbus", 20000: "DNP3", 102: "S7comm",
         44818: "EtherNet/IP", 2222: "EtherNet/IP", 4840: "OPC UA",
         5094: "HART-IP", 5095: "HART-IP"}


# ---------------- Modbus/TCP ----------------
MODBUS_READ = {1, 2, 3, 4}
MODBUS_WRITE = {5, 6, 15, 16, 22, 23}

def modbus_kind(p):
    if len(p) < 8:                      # MBAP header (7 bytes) + function code
        return None
    fc = p[7] & 0x7F
    return "write" if fc in MODBUS_WRITE else "read" if fc in MODBUS_READ else None


# ---------------- S7comm (TPKT + COTP + S7) ----------------
S7_READ = {0x04}
S7_ENG = {0x05, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x28, 0x29}

def s7_kind(p):
    if len(p) < 17 or p[0] != 0x03:     # TPKT version 3
        return None
    s7 = 4 + p[4] + 1                   # TPKT(4) + COTP(length byte + 1)
    if len(p) <= s7 + 10 or p[s7] != 0x32 or p[s7 + 1] != 1:   # S7 magic, ROSCTR=Job
        return None
    fc = p[s7 + 10]
    return "write" if fc in S7_ENG else "read" if fc in S7_READ else None


# ---------------- DNP3 ----------------
DNP3_READ = {0x01}
DNP3_CONTROL = {0x02, 0x03, 0x04, 0x05, 0x06, 0x0D, 0x0E, 0x10, 0x11, 0x12}

def dnp3_kind(p):
    # link header = 10 bytes, then transport byte, app control byte, function code
    if len(p) < 13 or p[0] != 0x05 or p[1] != 0x64:
        return None
    fc = p[12]
    if fc >= 0x80:                      # responses
        return None
    return "write" if fc in DNP3_CONTROL else "read" if fc in DNP3_READ else None


# ---------------- EtherNet/IP (explicit messaging, SendRRData) ----------------
CIP_READ = {0x01, 0x0E, 0x4C}           # Get_Attributes_All, Get_Attribute_Single, Read Tag
CIP_WRITE = {0x02, 0x10, 0x4D, 0x53}    # Set_Attributes_All, Set_Attribute_Single, Write Tag

def enip_kind(p):
    if len(p) < 44:
        return None
    cmd = int.from_bytes(p[0:2], "little")
    if cmd != 0x006F:                   # only SendRRData carries CIP requests here
        return None
    off = 32                            # 24 header + 4 interface handle + 2 timeout + 2 item count
    alen = int.from_bytes(p[off + 2:off + 4], "little")
    off += 4 + alen                     # skip address item
    if len(p) < off + 5:
        return None
    if int.from_bytes(p[off:off + 2], "little") != 0x00B2:   # unconnected data item
        return None
    svc = p[off + 4]
    if svc & 0x80:                      # response bit
        return None
    return "write" if svc in CIP_WRITE else "read" if svc in CIP_READ else None


# ---------------- OPC UA binary (only works when SecurityMode = None) ----------------
OPC_READ = {631, 527, 787, 751, 826}    # Read, Browse, CreateSubscription, CreateMonitoredItems, Publish
OPC_WRITE = {673, 712}                  # Write, Call

def opcua_kind(p):
    if len(p) < 28 or p[0:3] != b"MSG":
        return None
    if p[24] != 0x01 or p[25] != 0x00:  # four-byte NodeId in namespace 0
        return None
    svc = int.from_bytes(p[26:28], "little")
    return "write" if svc in OPC_WRITE else "read" if svc in OPC_READ else None


# ---------------- HART-IP (header + HART command number) ----------------
# HART-IP header (8 bytes): version, message type (0 = request), message ID (3 = HART PDU),
# status, sequence (2), byte count (2). The HART PDU follows: delimiter, address, command number.
HART_READ = {0, 1, 2, 3, 7, 8, 9, 11, 12, 13, 14, 15, 16, 20, 21, 33, 48, 50}
HART_WRITE = {6, 17, 18, 19, 22, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 49, 51}

def hartip_kind(p):
    if len(p) < 12 or p[0] != 1 or p[1] != 0 or p[2] != 3:   # requests carrying a HART PDU only
        return None
    cmd_off = 14 if p[8] & 0x80 else 10        # long frame = 5-byte address, short frame = 1 byte
    if len(p) <= cmd_off:
        return None
    cmd = p[cmd_off]
    return "write" if cmd in HART_WRITE else "read" if cmd in HART_READ else None


DECODERS = {"Modbus": modbus_kind, "S7comm": s7_kind, "DNP3": dnp3_kind,
            "EtherNet/IP": enip_kind, "OPC UA": opcua_kind, "HART-IP": hartip_kind}


def request_kind(proto, payload):
    fn = DECODERS.get(proto)
    return fn(payload) if fn else None


def flow_direction(sport, dport):
    """Return (protocol, is_request) for a packet, or None if neither port is an ICS port.
    If BOTH ports look like ICS ports (e.g. a Modbus reply from port 502 to a client whose
    random source port happens to be 2222), the lower port is treated as the service port."""
    s_ok, d_ok = sport in PORTS, dport in PORTS
    if s_ok and d_ok:
        return (PORTS[sport], False) if sport < dport else (PORTS[dport], True)
    if d_ok:
        return PORTS[dport], True
    if s_ok:
        return PORTS[sport], False
    return None


# ---------------- signature checks (used for UDP, where ports alone are unreliable) ----------------
_OPC_TYPES = {b"HEL", b"ACK", b"OPN", b"MSG", b"CLO", b"ERR", b"RHE"}
_ENIP_CMDS = {0x0004, 0x0063, 0x0064, 0x0065, 0x0066, 0x006F, 0x0070}


def looks_like(proto, p):
    """True if the payload plausibly belongs to the protocol (header signature + length check).
    This stops DNS/NTP/VPN packets with an unlucky random port from being counted as ICS traffic."""
    if proto == "Modbus":
        return len(p) >= 8 and p[2] == 0 and p[3] == 0 and int.from_bytes(p[4:6], "big") == len(p) - 6
    if proto == "S7comm":
        return len(p) >= 7 and p[0] == 0x03 and p[1] == 0x00 and int.from_bytes(p[2:4], "big") == len(p)
    if proto == "DNP3":
        return len(p) >= 10 and p[0] == 0x05 and p[1] == 0x64
    if proto == "EtherNet/IP":
        if (len(p) >= 24 and int.from_bytes(p[0:2], "little") in _ENIP_CMDS
                and int.from_bytes(p[2:4], "little") == len(p) - 24):
            return True
        # implicit I/O on UDP 2222: item count 2, sequenced/connected address item
        return (len(p) >= 8 and int.from_bytes(p[0:2], "little") == 2
                and int.from_bytes(p[2:4], "little") in (0x8002, 0x00A1))
    if proto == "OPC UA":
        return (len(p) >= 8 and p[0:3] in _OPC_TYPES and chr(p[3]) in "FCA"
                and int.from_bytes(p[4:8], "little") == len(p))
    if proto == "HART-IP":
        return len(p) >= 8 and p[0] == 1 and p[1] in (0, 1, 2, 3, 15) and p[2] <= 10
    return False


# ---------------- role classification (shared by ics_vista.py and alerts.py) ----------------
SERVER_RATIO_MIN = 0.80        # share of ICS payload packets sent as server -> field controller
WRITE_SHARE_ENG = 0.05         # >=5% of read/write requests are writes/eng -> engineering workstation
FANOUT_SUPERVISORY_MIN = 5     # a client talking to >=5 distinct controllers -> supervisory system
                               # (set to 10**9 to reproduce the earlier write-share-only rule)


def classify_role(as_client, as_server, reads, writes, n_peers, min_evidence=1):
    total = as_client + as_server
    if total < min_evidence:
        return "unknown"
    if as_server / total >= SERVER_RATIO_MIN:
        return "field_controller"
    rw = reads + writes
    if rw < min_evidence:
        return "unknown"                       # a client whose requests we cannot decode
    if n_peers >= FANOUT_SUPERVISORY_MIN:      # high fan-out polling = supervisory, even with some writes
        return "supervisory"
    return "engineering_workstation" if writes / rw >= WRITE_SHARE_ENG else "supervisory"
