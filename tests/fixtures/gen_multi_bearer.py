"""GTPv2-C capture for the old make_mock_callflow() scenario (pcap_web_parser).

    python3 gen_multi_bearer.py multi_bearer.pcap
    python3 gen_multi_bearer.py cups.pcap --cups

One UE, MME 10.10.2.72 / SGW 10.10.1.71 / PGW 10.10.3.73 (S11 + S5/S8, no CUPS):
  1-6    Attach: Create Session (LBI 5) + Modify Bearer
  7-10   Network-initiated Create Bearer: 3 dedicated bearers -> EBI 9, 10, 11
  11-16  Second PDN connection (APN "ims", LBI 7) + Modify Bearer
  17-20  Delete Bearer EBI 10
  21-24  Delete Session for the second PDN (LBI 7)

User-plane TEIDs are the values from the mock. As in the mock, the eNodeB
S1-U address is the MME's address (kept so the capture stays as it was; the
call flow now assigns tunnel ends by interface type). All identifiers are test values (IMSI 001010000000001).

--cups: the same messages between MME / SGW-C / PGW-C, but every user-plane
F-TEID (S1-U, S5/S8-U) carries the address of the SGW-U 10.10.11.71, the
PGW-U 10.10.13.73 or the eNodeB 10.10.20.1, as the user-plane functions
allocate them over PFCP. No GTP-C node owns a tunnel address.
"""
import struct, sys

MME, SGW, PGW = "10.10.2.72", "10.10.1.71", "10.10.3.73"
ENB = MME
CUPS = "--cups" in sys.argv[2:]
# Address carried in user-plane F-TEIDs (interface types 0, 1, 4, 5)
USER_PLANE = {MME: "10.10.20.1", SGW: "10.10.11.71", PGW: "10.10.13.73"} if CUPS else {}

def ip(a): return bytes(int(x) for x in a.split("."))

# ---------------------------------------------------------------- IEs (TS 29.274 8.x)
def ie(t, val, inst=0): return struct.pack(">BHB", t, len(val), inst & 0x0F) + val
def tbcd(d):
    d = d + "F" * (len(d) % 2)
    return bytes(int(d[i + 1], 16) << 4 | int(d[i], 16) for i in range(0, len(d), 2))
def imsi(): return ie(1, tbcd("001010000000001"))
def msisdn(): return ie(76, tbcd("15551230001"))
def mei(): return ie(75, tbcd("3534900123456780"))
def cause(c=16): return ie(2, bytes([c, 0]))
def recovery(n): return ie(3, bytes([n]))
def apn(name): return ie(71, b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")))
def ambr(ul, dl): return ie(72, struct.pack(">II", ul, dl))
def ebi(n, inst=0): return ie(73, bytes([n]), inst)
def indication(*octets): return ie(77, bytes(octets))
def pco(): return ie(78, bytes([0x80, 0x00, 0x0D, 0x00, 0x00, 0x0A, 0x00]))
def paa(addr): return ie(79, bytes([1]) + ip(addr))
def rat(): return ie(82, bytes([6]))
def serving_network(): return ie(83, bytes([0x00, 0xF1, 0x10]))            # MCC 001 / MNC 01
def uli(): return ie(86, bytes([0x18]) + bytes([0x00, 0xF1, 0x10]) + struct.pack(">H", 0x0001)
                     + bytes([0x00, 0xF1, 0x10]) + struct.pack(">I", 0x00012301))
def fteid(iface, teid, addr, inst=0):
    if iface in (0, 1, 4, 5):
        addr = USER_PLANE.get(addr, addr)
    return ie(87, bytes([0x80 | iface]) + struct.pack(">I", teid) + ip(addr), inst)
def bearer_ctx(*ies, inst=0): return ie(93, b"".join(ies), inst)
def charging_id(n): return ie(94, struct.pack(">I", n))
def charging_chars(): return ie(95, b"\x08\x00")
def pdn_type(): return ie(99, bytes([1]))
def ue_tz(): return ie(114, bytes([0x40, 0x00]))
def apn_restriction(): return ie(127, bytes([0]))
def selection_mode(): return ie(128, bytes([0]))

def qos(qci, pl, gbr_kbps=0, mbr_kbps=0, pci=1, pvi=0):
    flags = (pci << 6) | (pl << 2) | pvi
    five = lambda n: n.to_bytes(5, "big")
    return ie(80, bytes([flags, qci]) + five(mbr_kbps) + five(mbr_kbps) + five(gbr_kbps) + five(gbr_kbps))

def tft_create(pf_id, remote, port, proto=17):
    """TS 24.008 10.5.6.12: Create new TFT, one bidirectional packet filter"""
    comps = (bytes([0x10]) + ip(remote) + ip("255.255.255.255")     # IPv4 remote address
             + bytes([0x30, proto])                                   # protocol identifier
             + bytes([0x50]) + struct.pack(">H", port))               # single remote port
    pf = bytes([0x30 | pf_id, 255 - pf_id, len(comps)]) + comps       # direction 3 = bidirectional
    return ie(84, bytes([(1 << 5) | 1]) + pf)

def gtpc(msg, teid, seq, *ies):
    body = b"".join(ies)
    return struct.pack(">BBHI", 0x48, msg, len(body) + 8, teid) + struct.pack(">I", seq << 8) + body

# ---------------------------------------------------------------- frames
def frame(src, dst, payload):
    udp = struct.pack(">HHHH", 2123, 2123, 8 + len(payload), 0) + payload
    iph = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0x4000, 64, 17, 0, ip(src), ip(dst))
    return b"\x00\x0b\xcd\xb1\x8c\x4e\x00\x1a\xe2\x00\x27\xc2\x08\x00" + iph + udp

pkts = []
def send(src, dst, msg, teid, seq, *ies): pkts.append(frame(src, dst, gtpc(msg, teid, seq, *ies)))

CSREQ, CSRSP, MBREQ, MBRSP = 32, 33, 34, 35
CBREQ, CBRSP, DBREQ, DBRSP = 95, 96, 99, 100
DSREQ, DSRSP = 36, 37

# Control-plane TEIDs (not in the mock, needed on the wire)
MME_S11, SGW_S11 = 0x0A000011, 0x0B000011
SGW_S5C_1, PGW_S5C_1 = 0x0B000051, 0x0C000051      # PDN 1 (LBI 5)
SGW_S5C_2, PGW_S5C_2 = 0x0B000052, 0x0C000052      # PDN 2 (LBI 7)

# ================================================================ PDN 1, LBI 5
# mock 1
send(MME, SGW, CSREQ, 0, 1,
     imsi(), msisdn(), mei(), uli(), serving_network(), rat(), indication(0x00, 0x00, 0x00, 0x00),
     fteid(10, MME_S11, MME), fteid(7, 0, PGW, inst=1),
     apn("internet"), selection_mode(), pdn_type(), paa("0.0.0.0"), apn_restriction(), ambr(50000, 100000),
     pco(), bearer_ctx(ebi(5), qos(9, 9)), recovery(3), ue_tz(), charging_chars())
# mock 2
send(SGW, PGW, CSREQ, 0, 2,
     imsi(), msisdn(), mei(), uli(), serving_network(), rat(),
     fteid(6, SGW_S5C_1, SGW), apn("internet"), selection_mode(), pdn_type(), paa("0.0.0.0"),
     apn_restriction(), ambr(50000, 100000), pco(),
     bearer_ctx(ebi(5), fteid(4, 123, SGW, inst=2), qos(9, 9)), recovery(7), ue_tz(), charging_chars())
# mock 3
send(PGW, SGW, CSRSP, SGW_S5C_1, 2,
     cause(), fteid(7, PGW_S5C_1, PGW, inst=1), paa("100.64.0.10"), apn_restriction(), ambr(50000, 100000),
     bearer_ctx(ebi(5), cause(), fteid(5, 321, PGW, inst=2), charging_id(0x5001)), recovery(9))
# mock 4
send(SGW, MME, CSRSP, MME_S11, 1,
     cause(), fteid(11, SGW_S11, SGW), fteid(7, PGW_S5C_1, PGW, inst=1), paa("100.64.0.10"),
     apn_restriction(), ambr(50000, 100000),
     bearer_ctx(ebi(5), cause(), fteid(1, 132, SGW), fteid(5, 321, PGW, inst=2), charging_id(0x5001)),
     recovery(7))
# mock 5
send(MME, SGW, MBREQ, SGW_S11, 3,
     bearer_ctx(ebi(5), fteid(0, 213, ENB)))
# mock 6
send(SGW, MME, MBRSP, MME_S11, 3,
     cause(), bearer_ctx(ebi(5), cause(), fteid(1, 132, SGW)))

# ================================================================ Dedicated bearers 9, 10, 11 on LBI 5
DEDICATED = [  # (PGW S5-U, SGW S1-U, eNB S1-U, SGW S5-U, EBI, QCI, GBR kbps, remote, port)
    (345, 145, 245, 155, 9, 1, 128, "10.20.0.1", 5060),
    (346, 146, 246, 156, 10, 2, 2000, "10.20.0.2", 5004),
    (347, 147, 247, 157, 11, 6, 0, "10.20.0.3", 8080),
]
# mock 7: PGW -> SGW, EBI 0 in each bearer context (the MME assigns EBIs)
send(PGW, SGW, CBREQ, SGW_S5C_1, 0x100,
     ebi(5),
     *[bearer_ctx(ebi(0), tft_create(i + 1, r, port), fteid(5, pgw_u, PGW, inst=1),
                  qos(qci, 2, g, g), charging_id(0x5100 + e))
       for i, (pgw_u, _, _, _, e, qci, g, r, port) in enumerate(DEDICATED)])
# mock 8: SGW -> MME
send(SGW, MME, CBREQ, MME_S11, 0x101,
     ebi(5),
     *[bearer_ctx(ebi(0), tft_create(i + 1, r, port), fteid(1, sgw_u, SGW), fteid(5, pgw_u, PGW, inst=1),
                  qos(qci, 2, g, g), charging_id(0x5100 + e))
       for i, (pgw_u, sgw_u, _, _, e, qci, g, r, port) in enumerate(DEDICATED)])
# mock 9: MME -> SGW with the assigned EBIs
send(MME, SGW, CBRSP, SGW_S11, 0x101,
     cause(),
     *[bearer_ctx(ebi(e), cause(), fteid(0, enb_u, ENB), fteid(1, sgw_u, SGW, inst=1))
       for (_, sgw_u, enb_u, _, e, _, _, _, _) in DEDICATED])
# mock 10: SGW -> PGW
send(SGW, PGW, CBRSP, PGW_S5C_1, 0x100,
     cause(),
     *[bearer_ctx(ebi(e), cause(), fteid(4, sgw5, SGW, inst=2), fteid(5, pgw_u, PGW, inst=3))
       for (pgw_u, _, _, sgw5, e, _, _, _, _) in DEDICATED])

# ================================================================ PDN 2, LBI 7 (APN "ims")
# mock 21: the S11 tunnel already exists, so the header carries the SGW S11 TEID
send(MME, SGW, CSREQ, SGW_S11, 4,
     imsi(), msisdn(), uli(), serving_network(), rat(),
     fteid(10, MME_S11, MME), fteid(7, 0, PGW, inst=1),
     apn("ims"), selection_mode(), pdn_type(), paa("0.0.0.0"), apn_restriction(), ambr(10000, 10000),
     pco(), bearer_ctx(ebi(7), qos(5, 2)), ue_tz())
# mock 22
send(SGW, PGW, CSREQ, 0, 5,
     imsi(), msisdn(), uli(), serving_network(), rat(),
     fteid(6, SGW_S5C_2, SGW), apn("ims"), selection_mode(), pdn_type(), paa("0.0.0.0"),
     apn_restriction(), ambr(10000, 10000), pco(),
     bearer_ctx(ebi(7), fteid(4, 1123, SGW, inst=2), qos(5, 2)), ue_tz())
# mock 23
send(PGW, SGW, CSRSP, SGW_S5C_2, 5,
     cause(), fteid(7, PGW_S5C_2, PGW, inst=1), paa("100.64.0.11"), apn_restriction(), ambr(10000, 10000),
     bearer_ctx(ebi(7), cause(), fteid(5, 3321, PGW, inst=2), charging_id(0x7001)))
# mock 24
send(SGW, MME, CSRSP, MME_S11, 4,
     cause(), fteid(11, SGW_S11, SGW), fteid(7, PGW_S5C_2, PGW, inst=1), paa("100.64.0.11"),
     apn_restriction(), ambr(10000, 10000),
     bearer_ctx(ebi(7), cause(), fteid(1, 1132, SGW), fteid(5, 3321, PGW, inst=2), charging_id(0x7001)))
# mock 25
send(MME, SGW, MBREQ, SGW_S11, 6,
     bearer_ctx(ebi(7), fteid(0, 2213, ENB)))
# mock 26
send(SGW, MME, MBRSP, MME_S11, 6,
     cause(), bearer_ctx(ebi(7), cause(), fteid(1, 1132, SGW)))

# ================================================================ Delete Bearer EBI 10 (LBI 5 keeps 5, 9, 11)
# mock 31-34: the bearer to delete goes in EBI instance 1 (instance 0 would be an LBI: whole PDN)
send(PGW, SGW, DBREQ, SGW_S5C_1, 0x102, ebi(10, inst=1), cause(8))
send(SGW, MME, DBREQ, MME_S11, 0x103, ebi(10, inst=1), cause(8))
send(MME, SGW, DBRSP, SGW_S11, 0x103, cause(), bearer_ctx(ebi(10), cause()))
send(SGW, PGW, DBRSP, PGW_S5C_1, 0x102, cause(), bearer_ctx(ebi(10), cause()))

# ================================================================ Delete Session for PDN 2 (LBI 7)
# mock 35-38
send(MME, SGW, DSREQ, SGW_S11, 7, ebi(7), indication(0x00, 0x08, 0x00, 0x00))
send(SGW, PGW, DSREQ, PGW_S5C_2, 8, ebi(7))
send(PGW, SGW, DSRSP, SGW_S5C_2, 8, cause())
send(SGW, MME, DSRSP, MME_S11, 7, cause())

out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
t0 = 1_760_800_000
for i, p in enumerate(pkts):
    us = 150_000 * i + (i * 7919) % 50_000
    out += struct.pack("<IIII", t0 + us // 1_000_000, us % 1_000_000, len(p), len(p)) + p
open(sys.argv[1], "wb").write(out)
print(len(pkts), "packets")
