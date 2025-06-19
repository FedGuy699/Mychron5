from scapy.all import *
import time

# Full device path for sending packets (from your get_if_list output)
iface_send = r"\\Device\\NPF_{26827995-6805-422C-BA17-07080BDF0E50}"

# Friendly interface name for sniffing (from get_windows_if_list output)
iface_sniff = "Wi-Fi"

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
synack = sr1(ip/syn, timeout=2, iface=iface_send, verbose=0)
if not synack:
    print("[!] No SYN-ACK received.")
    exit()

print("[*] Received SYN-ACK:")
synack.show()

ack_seq = syn_seq + 1
ack_ack = synack.seq + 1

ack = TCP(
    sport=src_port,
    dport=dst_port,
    flags="A",
    seq=ack_seq,
    ack=ack_ack,
    window=64240
)

print("[*] Sending ACK...")
send(ip/ack, iface=iface_send, verbose=0)
print("[*] ACK sent.")

payload = bytes.fromhex("3c685354435008000000003e00000000060800003c535443500e003e")

data_pkt = TCP(
    sport=src_port,
    dport=dst_port,
    flags="PA",
    seq=ack_seq,
    ack=ack_ack,
    window=64240
)

print("[*] Sending initial data...")
send(ip/data_pkt/payload, iface=iface_send, verbose=0)
ack_seq += len(payload)
print("[*] Data sent.")

def packet_callback(pkt):
    if IP in pkt and TCP in pkt:
        if pkt[IP].src == dst_ip and pkt[TCP].sport == dst_port:
            if Raw in pkt:
                data = pkt[Raw].load
                hex_data = data.hex()
                ascii_data = ''.join([chr(b) if 32 <= b < 127 else '.' for b in data])
                print(f"[+] {len(data)} bytes received:")
                print(f"    HEX   : {hex_data}")
                print(f"    ASCII : {ascii_data}")
            else:
                print("[+] MyChron sent a TCP packet (no payload)")

print("[*] Listening for response from MyChron (10 seconds)...")
sniff(
    iface=iface_sniff,
    filter=f"tcp and src host {dst_ip} and src port {dst_port} and dst port {src_port}",
    prn=packet_callback,
    timeout=10,
    store=0
)
