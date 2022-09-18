from Ip import *

# Couche UDP

class UDP: 
  def __init__(self):
    self.ip=IP()
    self.sPort="" 
    self.dPort="" 
    self.length="" 
    self.checksum="" 
    self.trame_udp=[]

  def debut_udp(self, trame):
     ip_debut= trame[14:] #14 premiers octets appartiennent à ethernet
     l = self.ip.determine_option_length(trame) + 20
     self.trame_udp= ip_debut[l:] #La trame udp commence directement apres la fin des options de la trame ip 
     return self.trame_udp 

  def determine_source_port(self, trame):
    """ Fonction qui determine le port source d'une trame udp"""
    p= "".join(trame[0:2])
    self.sPort= p
    return int(p, 16) 
  
  def determine_dest_port(self, trame):
    """Fonction qui determine le port destination d'une trame udp"""
    p= "".join(trame[2:4])
    self.dport=p 
    return int(p, 16)  

  def determine_length(self, trame): 
    l="".join(trame[4:6])
    self.length= int(l, 16)
    return self.length

  def determine_checksum(self, trame): 
    c= "".join(trame[6:8])
    self.checksum= "0x"+c
    return self.checksum