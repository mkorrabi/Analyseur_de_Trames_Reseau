import copy
from Udp import *

#DNS
class DNS:

  def __init__(self):
    self.udp=UDP()
    self.trame_DNS=[]
    self.id=""
    self.flag="" 
    self.flagsdic={"Qr":"", "Opcode":"", "Aa":"", "Tc": "", "Rd":"", "Ra":"", "Z":"", "Rcode":""}
    self.no_questions= ""
    self.no_rep=""
    self.no_authority= ""
    self.no_add= ""
    self.questions=[] #Liste de toutes les questions 
    self.debut_answers=[] #Debut de la section des reponses dans la trame 
    self.answers=[] #Liste de toutes les reponses 
    self.debut_authority=[] #Debut de la section authority dans la trame 
    self.authority=[] #Liste de tout Authority 
    self.debut_additional=[] #Debut de la section additional dans la trame 
    self.additional=[] #Liste de tout Aditional 


  def debut_DNS(self, trame):
    trame_udp= self.udp.debut_udp(trame) #La trame udp commence directement apres la fin des options de la trame ip 
    self.trame_DNS= trame_udp[8:]
    return self.trame_DNS 

  def determine_id(self, trame):
    self.id= "".join(trame[:2]) #deux premiers octets de la trame dns consacré au id
    return self.id

  def determine_flags(self, trame):
    flags="".join(trame[2:4]) 
    self.flag=flags
    binflags="" 
    for i in flags:
      binflags+=  bin(int(i, 16))[2:].zfill(len(i)*4)
    self.flagsdic["Qr"] = binflags[0]
    self.flagsdic["Opcode"] = binflags[1:5]
    self.flagsdic["Aa"] = binflags[5]
    self.flagsdic["Tc"] = binflags[6]
    self.flagsdic["Rd"] = binflags[7]
    self.flagsdic["Ra"] = binflags[8]
    self.flagsdic["Z"] = binflags[9]
    self.flagsdic["Rcode"] = binflags[10:14]
    return self.flagsdic 

  def determine_no_questions(self, trame):
    s=  "".join(trame[4:6])
    self.no_questions= int(s, 16)
    return self.no_questions
  
  def determine_no_rep(self, trame):
    s= "".join(trame[6:8])
    self.no_rep = int(s, 16)
    return self.no_rep

  def determine_no_authority(self, trame):
    s= "".join(trame[8:10])
    self.no_authority= int(s, 16)
    return self.no_authority 

  def determine_no_add(self, trame):
    s= "".join(trame[10:12])
    self.no_add= int(s, 16)
    return self.no_add 


  def compression_DNS(self, octet):
    """Une fonction qui renvoie le nombre d'octets a sauter pour recomencer la lecture"""
    binary="" 
    for i in octet: 
      binary+=bin(int(i, 16))[2:].zfill(len(i)*4) #Recuperer la valeure binaire sur 16 bits
    if binary[0]+binary[1] == '11': #On a bien un pointeur à cause des deu premiers bits 11 
      return(True, int(binary[2:], 2)) #On retourne le nombre d'octets a sauter
    else:
      return (False, 0) 

  def start_lecture(self, trameDns, nb):
    new = trameDns[nb:] #Retrouver le lieu où nous pouvons recommencer la lecture 


  def hex_to_ascii(self, ch): 
    bytes_obj = bytes.fromhex(ch)
    return bytes_obj.decode('ASCII')


  def name_rec(self, tr, name, trame, c=[]):
    if tr[0]=="00":
      if c==[]: #on pas eu de pointeur 
        return name, tr
      else:
        return name, c 
    #Sinon soit on est sur un caractere  normale (pas pointeur) soit on est sur un c0 (pointeur)
    (a, b)  = self.compression_DNS(tr[0]+tr[1])
    if a==False: #Pas un pointeur
      name+=tr[0] #On ajoute la valeure du code ascii
      if c!=[]: #Il s'agit d'une relecture 
        return self.name_rec(tr[1:], name, trame, c)
      else:
        return self.name_rec(tr[1:], name, trame) 
    else: #a=True 
      #On a un pointeur donc a=True on recupere b = nb octets a sauter  
      return self.name_rec(trame[b:], name, trame, tr[2:])

  def determine_questions(self, trame, nbquestion): 
    tr= copy.deepcopy(trame[12:])
    b=0
    for i in range(nbquestion):
      n, liste= self.name_rec(tr[b:], "", trame)
      dic= {"Name":self.hex_to_ascii(n), "Type":"".join(liste[0:2]), "Class":"".join(liste[2:4])}
      b=4 
      tr=liste
      self.questions.append(dic)
    #idiquier où la fonction determine_answer doit commencer sa lecture 
    #Fini la lecture des questions, donc l'octet prochain est le debut de la lecture des reponses 
    self.debut_answers= tr[4:]
    return self.questions

  def hex_to_dec(self, lis): 
    return ".".join([str((int(i, 16))) for i in lis]) 

  def determine_answer(self, nbreponses, trame):
    tr= copy.deepcopy(self.debut_answers)
    b=0
    for i in range(nbreponses):
      n, liste= self.name_rec(tr[b:], "", trame)
      dic= {"Name":self.hex_to_ascii(n), "Type":"".join(liste[0:2]), "Class":"".join(liste[2:4]), "TTL": "".join(liste[4:8]), "DatalENGTH": "".join(liste[8:10]), "addr":self.hex_to_dec(liste[10:])}
      b=14
      tr=liste
      self.answers.append(dic)
    #idiquier où la fonction determine_answer doit commencer sa lecture 
    #Fini la lecture des questions, donc l'octet prochain est le debut de la lecture des reponses 
    self.debut_authority= tr[14:]
    return self.answers


  def determine_authority(self, nbauthority, trame):
    tr= copy.deepcopy(self.debut_authority)
    b=0
    for i in range(nbauthority):
      n, liste= self.name_rec(tr[b:], "", trame)
      dic= {"Name":n, "Type":"".join(liste[0:2]), "Class":"".join(liste[2:4]), "TTL": "".join(liste[4:8]), "DatalENGTH": "".join(liste[8:10]), "addr":self.hex_to_dec(liste[10:])}
      b=14
      tr=liste
      self.authority.append(dic)
    #idiquier où la fonction determine_answer doit commencer sa lecture 
    #Fini la lecture des questions, donc l'octet prochain est le debut de la lecture des reponses 
    self.debut_additional= tr[14:]
    return self.authority 

  def determine_additional(self, nbadd, trame):
    tr= copy.deepcopy(self.debut_additional)
    b=0
    for i in range(nbadd):
      n, liste= self.name_rec(tr[b:], "", trame)
      dic= {"Name":n, "Type":"".join(liste[0:2]), "Class":"".join(liste[2:4]), "TTL": "".join(liste[4:8]), "DatalENGTH": "".join(liste[8:10]), "addr":self.hex_to_dec(liste[10:])}
      b=14
      tr=liste
      self.additional.append(dic)
    #idiquier où la fonction determine_answer doit commencer sa lecture 
    #Fini la lecture des questions, donc l'octet prochain est le debut de la lecture des reponses 
    self.debut_additional= tr[14:]
    return self.additional