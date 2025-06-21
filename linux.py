import time
import netifaces
from scapy.all import *

# Auto-detect interface bound to 10.0.0.2
iface = None
for i in netifaces.interfaces():
    addrs = netifaces.ifaddresses(i)
    if netifaces.AF_INET in addrs:
        for link in addrs[netifaces.AF_INET]:
            if link.get('addr') == '10.0.0.2':
                iface = i
                break
    if iface:
        break

if not iface:
    print("[!] Could not find interface with IP 10.0.0.2. Set iface manually.")
    exit()

print(f"[*] Using interface: {iface}")


src_ip = "10.0.0.2"
dst_ip = "10.0.0.1"
src_port = 52523
dst_port = 2000

ip = IP(src=src_ip, dst=dst_ip, ttl=128, id=0xae59)
syn_seq = 0xf33e2db9

syn = TCP(
    sport=src_port,
    dport=dst_port,
    flags="S",
    seq=syn_seq,
    window=64240,
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
synack = sr1(ip/syn, timeout=2, iface=iface, verbose=0)
if not synack:
    print("[!] No SYN-ACK received.")
    exit()

print("[*] Received SYN-ACK:")
synack.show()

ack_seq = (syn_seq + 1) & 0xFFFFFFFF
ack_ack = (synack.seq + 1) & 0xFFFFFFFF

def ack(seq, ack, window):
    seq &= 0xFFFFFFFF
    ack &= 0xFFFFFFFF
    print(f"[DEBUG] Sending ACK packet seq={seq} ack={ack} window={window}")
    ack_reply = TCP(
        sport=src_port,
        dport=dst_port,
        flags="A",
        seq=seq,
        ack=ack,
        window=window
    )
    send(ip/ack_reply, iface=iface, verbose=0)

ack(ack_seq, ack_ack, 64240)



initial_payload = bytes.fromhex("40f52099d2d98c8d2811e216080045000044ae5e4000800638530a0000020a000001cd2b07d0748ec5530000196f5018faf0b63a00003c685354435008000000003e00000000060800003c535443500e003e")
print("[*] Sending initial data...")
data_pkt = TCP(
    sport=src_port,
    dport=dst_port,
    flags="PA",
    seq=ack_seq,
    ack=ack_ack,
    window=64240
)
send(ip/data_pkt/initial_payload, iface=iface, verbose=0)
ack_seq = (ack_seq + len(initial_payload)) & 0xFFFFFFFF
print("[*] Initial data sent.")
ack_ack = (synack.seq + 13) & 0xFFFFFFFF

ack(ack_seq, ack_ack, 64228)

ack_ack = (synack.seq + 29) & 0xFFFFFFFF
payload_2 = bytes.fromhex("40f52099d2d98c8d2811e21608004500007cae604000800638190a0000020a000001cd2b07d0748ec56f0000198b5018fad433ac00003c6853544e4340000000003e000000000000000010000100000000004000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000003c53544e4352003e")
data_pkt2 = TCP(
    sport=src_port,
    dport=dst_port,
    flags="PA",
    seq=ack_seq,
    ack=ack_ack,
    window=64212
)
send(ip/data_pkt2/payload_2, iface=iface, verbose=0)
ack_seq = (ack_seq + len(payload_2)) & 0xFFFFFFFF

ack_ack = (synack.seq + 41) & 0xFFFFFFFF

ack(ack_seq, ack_ack, 64228)

ack_ack = (synack.seq + 113) & 0xFFFFFFFF
payload_3 = bytes.fromhex("40f52099d2d98c8d2811e216080045000080ae624000800638130a0000020a000001cd2b07d0748ec5c3000019df5018fa80636c00003c685354435044000000003e000000000000000000000000e907000006000000130000000700000006000000000000000000000000000000e907000006000000130000000300000006000000000000003c5354435028023e")
data_pkt3 = TCP(
    sport=src_port,
    dport=dst_port,
    flags="PA",
    seq=ack_seq,
    ack=ack_ack,
    window=64128
)
send(ip/data_pkt3/payload_3, iface=iface, verbose=0)
ack_seq = (ack_seq + len(payload_3)) & 0xFFFFFFFF
ack_ack = (synack.seq + 125) & 0xFFFFFFFF

ack(ack_seq, ack_ack, 64116)

payload_4 = bytes.fromhex("40f52099d2d98c8d2811e216080045000040ae654000800638500a0000020a000001cd2b07d0748ec61b00001a4b5018fa14bf8c00003c685354435004000000003e000000003c5354435000003e")
data_pkt4 = TCP(
    sport=src_port,
    dport=dst_port,
    flags="PA",
    seq=ack_seq,
    ack=ack_ack,
    window=64020
)
send(ip/data_pkt4/payload_4, iface=iface, verbose=0)
