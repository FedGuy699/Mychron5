from scapy.all import *

# Set up IP and TCP parameters
ip = IP(src="10.0.0.2", dst="10.0.0.1", ttl=128, id=0xae59)
tcp = TCP(
    sport=52523,
    dport=2000,
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

packet = ip / tcp

send(packet, verbose=1)

response = sr1(packet, timeout=2)
if response:
    response.show()
else:
    print("No response received")

