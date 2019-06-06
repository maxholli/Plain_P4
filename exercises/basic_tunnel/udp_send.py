#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import argparse

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, hexdump
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP, Raw
from myTunnel_header import MyTunnel

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('ip_addr', type=str, help="The destination IP address to use")
    parser.add_argument('message', type=str, help="The message to include in packet")
    parser.add_argument('--dst_id', type=int, default=None, help='The myTunnel dst_id to use, if unspecified then myTunnel header will not be included in packet')
    args = parser.parse_args()

    addr = socket.gethostbyname(args.ip_addr)
    dst_id = args.dst_id
    iface = get_if()

    if (dst_id is not None):

        payload = Raw(load="Today is a good day, you bloody wanker.")
        inner_udp = UDP(dport=80,sport=1117)
        inner_ip = IP(dst="8.8.8.8",src="45.45.0.11")
        inner_headers = inner_ip/inner_udp/payload
        gtp_string = '03ff' + '%04x' % len(inner_headers) + '01234567'
        #gtp_inner_headers = Raw(load=bytes.fromhex(gtp_string))/inner_headers
        gtp_inner_headers = Raw(load=gtp_string.decode("hex"))/inner_headers
        outer_udp = UDP(dport=2152,sport=random.randint(49152,65535))
        outer_ip = IP(dst=addr)
        
        print "sending UDP"
        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        #pkt = pkt / IP(dst=addr) / UDP(dport=2152, sport=random.randint(49152,65535)) / IP(dst='12.3.4.5',src='10.0.0.1') / UDP(dport=8000, sport=8001) / args.message
        pkt = pkt / outer_ip / outer_udp / gtp_inner_headers
    else:
        print "sending on interface {} to IP addr {}".format(iface, str(addr))
        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt / IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / args.message

    pkt.show2()
#    hexdump(pkt)
#    print "len(pkt) = ", len(pkt)
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
