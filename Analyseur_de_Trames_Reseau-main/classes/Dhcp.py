#DHCP
 
class DHCP:

  def __init__(self):
    self.op="" 
    self.htypeval="" 
    self.htype="" #A determiner parmi plueisurs 
    self.hlen=0 
    self.hops="" 
    self.xid="" 
    self.secs=0 
    self.flags= {"R":"", "B":""} 
    self.ciaddr="" 
    self.yiaddr="" 
    self.siaddr="" 
    self.giaddr="" 
    self.chaddr="" 
    self.sname="" 
    self.file="" 
    self.options="" 


  def determine_op(self, trame): 
    """l'argument trame est une trame dhcp"""
    self.op= trame[0]
    return self.op 

  def determine_htypeVal(self, trame):
    v= "".join(trame[1:3]) 
    self.htypeval= int(v, 16)
    return self.htypeval


  def determine_htype(self, htypeval):
    if htypeval==1: 
      self.htype="Ethernet"
    elif htypeval==6:
      self.htype="IEE 802 Networks"
    elif htypeval==7:
      self.htype="ARCNET"
    elif htypeval==11:
      self.htype="LocaITalk"
    elif htypeval==12:
      self.htype="LocaINet (IBM PCNet or SYTEK LocaINET)"
    elif htypeval==14:
      self.htype="SMDS"
    elif htypeval==15:
      self.htype="Frame Relay"
    elif htypeval==16:
      self.htype="Asynchronous Transfer mode (ATM)"
    elif htypeval==17:
      self.htype="HDLC"
    elif htypeval==18:
      self.htype="Fibre Channel"
    elif htypeval==19:
      self.htype="Asynchronous Transfer Mode (ATM)"
    elif htypeval==20:
      self.htype="Serial Line"
    
    return self.htype


  def determine_hlen(self, trame):
    val= "".join(trame[3:6])
    self.hlen= int(val, 16) #Dec 
    return self.hlen 


  def determine_hops(self, trame):
    self.hops= "".join(trame[6: 10])
    return self.hops

  def determine_xid(self, trame): 
    val="".join(trame[10:20])
    self.xid=int(val, 16)
    return self.xid

  def determine_secs(self, trame): 
    val="".join(trame[20:23])
    self.secs= int(val, 16)
    return self.secs


  def determine_flags(self, trame): 
    v= bin(int("".join(trame[23], 16))) 
    self.flags["B"] = v[2]
    self.flags["R"] = bin(int("".join(trame[24:30]), 16))[2:]
    self.flags["R"] = v[3:] + self.flags["R"]
    return self.flags
    

  def determine_ciaddr(self, trame):
    self.ciaddr=".".join(trame[30:40])
    return self.ciaddr

  
  def determine_yiaddr(self, trame):
    self.yiaddr=".".join(trame[40:50])
    return self.yiaddr

  def determine_siaddr(self, trame):
    self.siaddr=".".join(trame[50:60])
    return self.siaddr

  def determine_giaddr(self, trame):
    self.giaddr=".".join(trame[60:70])
    return self.giaddr

  def determine_chaddr(self, trame):
    self.chaddr="".join(trame[70:80])
    return self.chaddr

  def determine_sname(self, trame):
    self.sname="<"
    self.sname+="".join(trame[80:90])
    self.sname+=">"
    return self.sname

  
  def determine_file(self, trame):
    self.file="<"
    self.file+="".join(trame[90:100])
    self.file+=">"
    return self.file

  def determine_optionval(self, trame):
    val= trame[100] #100eme octet correspond au code de l'option 
    return val 

  def determine_option(self, trame): 
    v= self.determine_optionval(trame) 
    v= int(v, 16) #Recuperer la valeure de l'option en decimale 
    l_op= [1, 3, 15, 6, 12, 28, 43, 50, 51, 53, 54, 55, 57, 58, 59, 60, 61, 114, 116, 2, 224]
    if v in l_op: 
      if v==1: 
        self.option= "Subnet Mask"
      elif v==3: 
        self.option= "Router"
      elif v==15: 
        self.option= "Domain Name"
      elif v==6:
        self.option="Serveur de domaine"
      elif v==12:
        self.option="Nom d'hôte"
      elif v==28:
        self.option="Adresse de diffusion"
      elif v==43:
        self.option="Spécifique au fournisseur"
      elif v==50:
        self.option="Demande d'adresse"
      elif v==51:
        self.option="Adresse Heure"
      elif v==53:
        self.option="Type de message DHCP"
      elif v==54:
        self.option="Identifiant du serveur DHCP"
      elif v==55:
        self.option="Liste des paramètres"
      elif v==57:
        self.option="Taille maximale des messages DHCP"
      elif v==58:
        self.option="Temps de renouvellement"
      elif v==59:
        self.option="Temps de reliure"
      elif v==60:
        self.option="Identifiant de classe"
      elif v==61:
        self.option="Identité du client"
      elif v==114:
        self.option="Portail captif DHCP"
      elif v==116:
        self.option="Configuration automatique"
      elif v==2:
        self.option="Décalage horaire"
      elif v==224:
        self.option="Réservé (usage privé)"
    else: 
      self.option= "Option non traité par le programme"

    return self.option