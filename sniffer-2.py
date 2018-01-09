#!/usr/bin/python

import argparse
import socket
import struct 
from ctypes import *  



class IPHeader(Structure):
       
      
      _fields_ = [
         ("ihl",              c_ubyte, 4),
         ("version",          c_ubyte, 4),
         ("tos",              c_ubyte),
         ("len",              c_ushort),
         ("id",               c_ushort),
         ("offset",           c_ushort),
         ("ttl",              c_ubyte),
         ("protocol_num",     c_ubyte),
         ("sum",              c_ushort),
         ("src",              c_uint32),
         ("dst",              c_uint32)
      ]
    

      def __new__(self,data=None):
           
          ## lets make a structure of our packets captured 
             return self.from_buffer_copy(data)
      
      def __init__(self,data=None):
            
            self.source_ip = socket.inet_ntoa(struct.pack("@I",self.src))
            self.destination_ip = socket.inet_ntoa(struct.pack("@I",self.dst))
             
            self.protocols = {1:"ICMP",6:"TCP",17:"UDP"}
            try: 
              self.protocol = self.protocols[self.protocol_num]
            except:
              self.protocol = str(self.protocol_num)




def conn(proto):
    
    if(proto == "TCP"):
      print "Sniffer started sniffing TCP packets: "
      tcpSock = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)  
      tcpSock.bind(("0.0.0.0",0))
      sniffer(tcpSock)
    elif(proto =="UDP"):
      print "Sniffer started sniffing UDP packets: "
      udpSock = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_UDP)  
      udpSock.bind(("0.0.0.0",0))
      sniffer(udpSock)
    elif(proto == "ICMP"):
      print "Sniffer started sniffing ICMP packets: "
      icmpSock = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)  
      icmpSock.bind(("0.0.0.0",0))
      sniffer(icmpSock)


def sniffer(socks):
       sniff = socks
       
       # Get the raw Packets
       while True:
          try:   
            raw_pack = sniff.recvfrom(65535)[0]
            ip_header = IPHeader(raw_pack[0:20])
            if(ip_header.protocol == "TCP"):
               print "Protocol: " + ip_header.protocol + " Source: " + ip_header.source_ip + " Destination: " + ip_header.destination_ip
            elif(ip_header.protocol == "UDP"):
               print "Protocol: " + ip_header.protocol + " Source: " + ip_header.source_ip + " Destination: " + ip_header.destination_ip
            elif(ip_header.protocol == "ICMP"):
               print "Protocol: " + ip_header.protocol + " Source: " + ip_header.source_ip + " Destination: " + ip_header.destination_ip
           
          except KeyboardInterrupt:
             print "Exiting...."
             exit(0)

def main():
    parser = argparse.ArgumentParser("Packet Sniffer")
    parser.add_argument("-p","--protocol",type=str,help="Specify the protocol, packets to sniff!")
    args = parser.parse_args()
    proto  = args.protocol
    conn(proto)
    
main()









