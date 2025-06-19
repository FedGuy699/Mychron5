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
ack_seq = syn.seq + 1
ack_ack = synack.seq + 1

ack = TCP(
    sport=src_port,
    dport=dst_port,
    flags="A",
    seq=ack_seq,
    ack=ack_ack,
    window=0xfaf0
)

print("[*] Sending ACK to complete handshake...")
send(ip/ack)
print("[*] ACK sent.")

# Step 3: Send PSH with payload

psh_payload = bytes.fromhex("7fe40c74000000000000060900003c535443500f003e")

psh = TCP(
    sport=src_port,
    dport=dst_port,
    flags="PA",
    seq=ack_seq,
    ack=ack_ack,
    window=0xfaf0
)

print("[*] Sending PSH with payload...")
send(ip/psh/psh_payload)
print("[*] PSH sent.")

# Step 4: Sniff response

print("[*] Waiting for response...")
resp = sniff(filter=f"tcp and host {dst_ip} and port {dst_port}", timeout=5, count=5)

if resp:
    print(f"[*] Received {len(resp)} packets:")
    for pkt in resp:
        pkt.show()
else:
    print("[!] No response received.")
