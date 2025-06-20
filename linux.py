from scapy.all import *
import time

# Use wlan0 on Linux
iface = "wlan0"

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
send(ip/ack, iface=iface, verbose=0)
print("[*] ACK sent.")

payload = bytes.fromhex("3c685354435008000000003e00000000060800003c535443500e003e")

# Open log file
logfile = open("mychron_log.txt", "a")

def packet_callback(pkt):
    if IP in pkt and TCP in pkt:
        if pkt[IP].src == dst_ip and pkt[TCP].sport == dst_port:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            tcp_bytes = bytes(pkt[TCP])
            hex_dump = tcp_bytes.hex()

            print(f"[{timestamp}] TCP packet received, length {len(tcp_bytes)} bytes")
            logfile.write(f"[{timestamp}] TCP packet ({len(tcp_bytes)} bytes):\n")
            logfile.write(hex_dump + "\n\n")
            logfile.flush()

            # Send ACK immediately for PSH
            if "P" in pkt[TCP].flags:
                mychron_seq = pkt[TCP].seq
                mychron_len = len(pkt[TCP].payload)
                global ack_ack, ack_seq

                ack_ack = mychron_seq + mychron_len

                ack_reply = TCP(
                    sport=src_port,
                    dport=dst_port,
                    flags="A",
                    seq=ack_seq,
                    ack=ack_ack,
                    window=64240
                )
                send(IP(src=src_ip, dst=dst_ip)/ack_reply, iface=iface, verbose=0)
                print(f"[{timestamp}] Sent ACK immediately for PSH (ack={ack_ack})")

print("[*] Starting sniffer...")
sniffer = AsyncSniffer(
    iface=iface,
    filter=f"tcp and src host {dst_ip} and src port {dst_port} and dst port {src_port}",
    prn=packet_callback,
    store=0
)
sniffer.start()
time.sleep(0.2)  # Allow sniffer to fully initialize

print("[*] Sending initial data...")
data_pkt = TCP(
    sport=src_port,
    dport=dst_port,
    flags="PA",
    seq=ack_seq,
    ack=ack_ack,
    window=64240
)
send(ip/data_pkt/payload, iface=iface, verbose=0)
ack_seq += len(payload)
print("[*] Data sent.")

time.sleep(10)
sniffer.stop()
logfile.close()
print("[*] Sniffer stopped and log file closed.")
