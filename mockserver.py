# mockserver.py
import socket, struct, sys

def build_dns_response(transaction_id, mode="good"):
    """
    Build a DNS header that triggers different error checks in your client.
    """
    # Base flags: QR=1, RD=1, RA=1 (normal successful response, RCODE=0)
    flags = 0x8180  

    if mode == "bad_id":
        # We'll override the transaction ID later (not here)
        pass
    elif mode == "bad_qr":
        flags &= ~(1 << 15)   # set QR=0 (query), should trigger "QR bit incorrect"
    elif mode == "no_ra":
        flags &= ~(1 << 7)    # set RA=0, should trigger "Server does not support recursive queries"
    elif mode == "truncated":
        flags |= (1 << 9)     # set TC=1, should let you detect truncated response
    elif mode == "rcode1":
        flags = (flags & ~0xF) | 1  # set RCODE=1 (Format error)
    elif mode == "rcode2":
        flags = (flags & ~0xF) | 2  # set RCODE=2 (Server failure)
    elif mode == "rcode3":
        flags = (flags & ~0xF) | 3  # set RCODE=3 (NXDOMAIN)
    elif mode == "rcode4":
        flags = (flags & ~0xF) | 4  # set RCODE=4 (Not implemented)
    elif mode == "rcode5":
        flags = (flags & ~0xF) | 5  # set RCODE=5 (Refused)

    # Build DNS header (no Question/Answer sections for simplicity)
    header = struct.pack("!HHHHHH",
                         transaction_id,
                         flags,
                         1,  # QDCOUNT
                         0,  # ANCOUNT
                         0,  # NSCOUNT
                         0)  # ARCOUNT
    return header

# ---- Server loop ----
mode = sys.argv[1] if len(sys.argv) > 1 else "good"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 5300))
print(f"Fake DNS server running on port 5300 in mode={mode}")

while True:
    data, addr = sock.recvfrom(512)
    tid = struct.unpack("!H", data[:2])[0]

    if mode == "bad_id":
        tid = (tid + 1) & 0xFFFF  # force a mismatch

    response = build_dns_response(tid, mode)
    sock.sendto(response, addr)
    print(f"Sent response with mode={mode} to {addr}")
