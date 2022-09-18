from Ethernet import *  
from Ip import *
from Dns import *
from Dhcp import *
from Udp import *
from  verif import * 
import argparse 

#Recuperer le fichier source et destination 

#Instentiation de la classe ArgumentParser 
parser = argparse.ArgumentParser()

#Ajouter les arguments nécessaires
parser.add_argument("fic_src",type=str,help="Veuillez saisir le chemin vers le fichier contenant la trame\n")
parser.add_argument("fic_dest",type=str,help="Veuillez saisir le nom du fichier qui contiendra les analyses de la trame\n")
parser.add_argument("type", type=str,help="Veuillez préciser le type de votre trame (DNS/DHCP) en MAJ\n")
args = parser.parse_args()
v= verif(args.fic_src) #Instentiation de la classe verif 

if v.ouverture()!=None: #Nous avons reussit a ouvrir le fichier! 
  #On ouvre le fichier destination 
  trame=v.ouverture() #On recupere la trame  
  f= open(args.fic_dest, "w") #Ouvrir le fichier en mode append 
  #On commence les analyses par Ethernet 
  f.write("__________________________________________Ethernet_________________________________________\n")
  E= Ethernet()
  dest= E.adresse_mac(trame, "dest")
  f.write("Destination Mac Adress: "+E.dest+"\n")
  src= E.adresse_mac(trame, "src")
  f.write("Source Mac Adress: "+E.src+"\n")
  Type= E.trame_type(trame)
  f.write("Type: "+ Type[1]+" "+Type[0]+"\n")
  f.write("__________________________________________IP_____________________________________________\n")
  ip=IP() #Instentiation IP 
  v= ip.determine_version(trame)
  f.write("Version: "+v+"\n")
  ihl=ip.determine_ihl(trame)
  f.write("Header Length: "+ str(int(ihl)*4) +"bytes \n")
  L= ip.total_length(trame)
  f.write("Total length: "+L+"\n")
  i= ip.determine_id(trame)
  f.write("Identification: "+i+"\n")
  fl= ip.determine_flags(trame)
  f.write("Flag: "+fl+"\n")
  ff= ip.analyse_flag(ip.flag)
  f.write(ff+"\n")
  t= ip.ttl(trame)
  f.write("Time To Live: "+ str(t)+"\n")
  p= ip.determine_protocole(trame)
  f.write("Protocole: "+p[0]+" "+p[1] +" ("+ str(int(p[0], 16))+")\n") 
  c=ip.determine_checksum(trame)
  f.write("Checksum: 0x"+c+"\n")
  adds= ip.ip_src(trame)
  f.write("Source Adress: "+adds+"\n")
  adDest= ip.ip_dest(trame)
  f.write("Destination Adress: "+adDest+"\n")
  f.write("__________________________________________UDP_____________________________________________\n")
  u= UDP()
  trame_udp= u.debut_udp(trame)
  s= u.determine_source_port(trame_udp)
  f.write("Source Port: "+str(s)+ "\n")
  d= u.determine_dest_port(trame_udp)
  f.write("Destination Port: "+str(d)+ "\n")
  l= u.determine_length(trame_udp)
  f.write("Length: "+str(l)+ "\n")
  c= u.determine_checksum(trame_udp)
  f.write("Checksum: "+str(c)+ "\n")

  if args.type=="DNS":
    f.write("__________________________________________DNS_____________________________________________\n")
    dns= DNS()
    tr_dns= dns.debut_DNS(trame)
    id= dns.determine_id(tr_dns)
    f.write("Transaction Id: 0x"+ id+ "\n")
    ff= dns.determine_flags(tr_dns)
    f.write("Flag: 0x"+dns.flag+ "\n")
    dic= dns.flagsdic
    for i in dic: 
      f.write("     "+i+" "+ dic[i]+ "\n")
    noq= dns.determine_no_questions(tr_dns)
    f.write("Questions : "+str(noq)+ "\n")
    noa= dns.determine_no_rep(tr_dns)
    f.write("Answer RRs : "+str(noa)+ "\n")
    noAu= dns.determine_no_authority(tr_dns)
    f.write("Authority : "+str(noAu)+ "\n")
    noAdd= dns.determine_no_add(tr_dns)
    f.write("Aditional : "+str(noAdd)+ "\n")
    f.write("Query: "+"\n")
    if noq!=0: 
      Questions= dns.determine_questions(tr_dns, noq)
      for i in Questions: 
        f.write("    Name:"+i["Name"]+"\n")
        f.write("    Type:"+i["Type"]+"\n")
        f.write("    Class:"+i["Class"]+"\n")
    if noa!=0:
      Answers=  dns.determine_answer(noa, tr_dns)
      f.write("Answers: "+"\n")
      for i in Answers:
        f.write("    Name:"+i["Name"]+"\n")
        f.write("    Type:"+i["Type"]+"\n")
        f.write("    Class:"+i["Class"]+"\n")     
        f.write("    TTL:"+str(int(i["TTL"], 16))+"\n")
        f.write("    Data Length:"+str(int(i["DatalENGTH"], 16))+"\n")
        f.write("    Adress:"+i["addr"]+"\n") 
    if noAu!=0: 
      Authority= dns.determine_authority(noAu, tr_dns)
      f.write("Authority: "+"\n")
      for i in Authority:
        f.write("    Name:"+i["Name"]+"\n")
        f.write("    Type:"+i["Type"]+"\n")
        f.write("    Class:"+i["Class"]+"\n")     
        f.write("    TTL:"+str(int(i["TTL"], 16))+"\n")
        f.write("    Data Length:"+str(int(i["DatalENGTH"], 16))+"\n")
        f.write("    Adress:"+i["addr"]+"\n") 

    if noAdd!=0: 
      Additional= dns.determine_additional(noAdd, tr_dns)
      f.write("Additional: "+"\n")
      for i in Additional:
        f.write("    Name:"+i["Name"]+"\n")
        f.write("    Type:"+i["Type"]+"\n")
        f.write("    Class:"+i["Class"]+"\n")     
        f.write("    TTL:"+str(int(i["TTL"], 16))+"\n")
        f.write("    Data Length:"+str(int(i["DatalENGTH"], 16))+"\n")
        f.write("    Adress:"+i["addr"]+"\n")
  else: 
    f.write("__________________________________________DHCP________________________________________________\n")
    dh= DHCP()
    tr_dhcp= trame_udp[8:] #Trouver le debut de la trame dhcp 
    m= dh.determine_op(tr_dhcp)
    f.write("Message Type: "+m+"\n")
    h= dh.determine_htypeVal(tr_dhcp)
    ht= dh.determine_htype(h)
    f.write("Hardware Type: "+ht + "0x"+h+"\n")
    ln= dh.determine_hlen(tr_dhcp)
    f.write("Hardware adress length: "+ln+"\n")
    ops= dh.determine_hops(tr_dhcp)
    f.write("Hops: "+ops+"\n")
    flags= dh.determine_flags(tr_dhcp)
    f.write("Flags: "+ "\n")
    for i in flags: 
      f.write("Broadcast Flag: "+i["B"]+"\n")
      f.write("Reserved : "+i["R"]+"\n")
    
    p= dh.determine_ciaddr(tr_dhcp)
    f.write("Client IP adress: "+p+"\n")
    p= dh.determine_yiaddr(tr_dhcp)
    f.write("Your client IP adress: "+p+"\n")
    p= dh.determine_siaddr(tr_dhcp)
    f.write("Next Server IP adress : "+p+"\n")
    p= dh.determine_giaddr(tr_dhcp)
    f.write("Relay Agent IP Adress: "+p+"\n")
    p= dh.determine_sname(tr_dhcp)
    f.write("Server Host Name  "+p+"\n")
    p= dh.determine_file(tr_dhcp)
    f.write("Boot file name : "+p+"\n")
    p= dh.determine_option(tr_dhcp)
    f.write("Option : "+p+"\n")
    









  
  