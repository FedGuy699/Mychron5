from scapy.all import *

src_ip = "10.0.0.2"
dst_ip = "10.0.0.1"
src_port = 52523
dst_port = 2000

# Step 1: Send SYN
ip = IP(src=src_ip, dst=dst_ip, ttl=128, id=0xae59)
syn = TCP(
    sport=src_port,
    dport=dst_port,
    flags="S",
    seq=0x748ec552,
    window=0xfaf0,
    options=[
        ("MSS", 1460),
        ("NOP", None),
        ("WScale", 8),
        ("NOP", None),
        ("NOP", None),
        ("SAckOK", b"")
    ]
)

print("[*] Sending SYN...")
synack = sr1(ip/syn, timeout=2)
if not synack:
    print("[!] No SYN-ACK received.")
    exit()

print("[*] Received SYN-ACK:")
synack.show()

# Step 2: Send ACK to complete handshake
ack = TCP(
    sport=src_port,
    dport=dst_port,
    flags="A",
    seq=syn.seq + 1,
    ack=synack.seq + 1,
    window=0xfaf0
)

send(ip/ack)
print("[*] Sent ACK to complete handshake.")

