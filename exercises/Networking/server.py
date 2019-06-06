## Set up Server on specified IP

import socket
import argparse

parser = argparse.ArgumentParser(description="Server's IP")
parser.add_argument('ip', type=str, help='specify the server IP')
parser.add_argument('dst_port', type=int, default=6789, help='specify the port to listen on')

args = parser.parse_args()
print("server's IP is --", args.ip, args.dst_port)



UDP_IP_ADDRESS = args.ip
UDP_PORT_NO = args.dst_port

serverSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
serverSock.bind((UDP_IP_ADDRESS, UDP_PORT_NO))

while True:
        data, addr = serverSock.recvfrom(1024)
        print("Message: ", data)
        print(len(data))


'''                                                                                                   
TCPDUMP of a successful datagram                                                                      
14:32:15.440239 IP (tos 0x0, ttl 64, id 57753, offset 0, flags [DF], proto UDP (17), length 63)       
    10.1.1.1.33610 > 10.1.1.3.6789: UDP, length 35                                                    
'''
                
