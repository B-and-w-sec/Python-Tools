#!/usr/bin/python


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




def conn():
      sock = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)  
      sock.bind(("0.0.0.0",0))
      sock.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
      return sock 



def main():
       sniffer = conn()
       print "Sniffer Started: "
       # Get the raw Packets
       while True:
          try:   
            raw_pack = sniffer.recvfrom(65535)[0]
            ip_header = IPHeader(raw_pack[0:20])
            if(ip_header.protocol == "TCP"):
               print "Protocol: " + ip_header.protocol + " Source: " + ip_header.source_ip + " Destination: " + ip_header.destination_ip
      
          except KeyboardInterrupt:
             print "Exiting...."
             exit(0)

main()


