## Send a UDP datagram to IP

import socket
import argparse
from scapy.all import Ether, IP, UDP, Raw, raw, send

#from udp import UdpTarget

parser = argparse.ArgumentParser(description="Server's IP")
parser.add_argument('ip', type=str, help='specify the destination IP')
parser.add_argument('dst_port', type=int, default=6789, help='specify the UDP destination port')

args = parser.parse_args()
print("destination Ip is --", args.ip)

GTP_PORT = 2152

UDP_IP_ADDRESS = args.ip
UDP_PORT_NO = args.dst_port
#Message = "Hello, original dest_ip = " + args.ip + 'p' + str(UDP_PORT_NO)

payload = Raw(load="Today is a good day, you bloody wanker.")
inner_udp = UDP(dport=80,sport=1117)
inner_ip = IP(dst="10.1.1.1",src="1.2.3.4")
inner_headers = inner_ip/inner_udp/payload
gtp_string = '03ff' + '%04x' % len(inner_headers) + '01234567'
gtp_inner_headers = Raw(load=bytes.fromhex(gtp_string))/inner_headers
outer_udp = UDP(dport=GTP_PORT,sport=1117)
outer_ip = IP(dst=UDP_IP_ADDRESS,src='10.0.0.1')

Message = outer_ip/outer_udp/gtp_inner_headers
print(raw(Message).hex())
## final message should look like eth/ip/udp/ip/udp/raw
send(Message,iface='lo0')
