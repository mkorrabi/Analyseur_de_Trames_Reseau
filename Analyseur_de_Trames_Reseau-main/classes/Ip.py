class IP(): 
  def __init__(self):
    self.version=""
    self.IHL=""
    self.tos="" 
    self.taille="" 
    self.id="" 
    self.flag={"R":"", "DF":"", "MF":""}
    self.fo="" 
    self.TTL=0
    self.protocole=""
    self.header_checksum=""
    self.ipsrc=""
    self.ipdest=""
    self.option_length=0 
    self.option="" 

  def determine_version(self, trame): 
    self.version= str(trame[14])[0]
    return self.version 

  def determine_ihl(self, trame):
     #ihl se trouve aprés le type de l'entete ethernet 
     oct= str(trame[14])
     self.IHL= int(oct[1], 16)
     return self.IHL


  def determine_tos(self, trame): 
    t= str(int(trame[15], 16)) 
    self.tos= t 
    return t 


  def total_length(self, trame):
    ll=""
    for i in range(16, 18):
      ll+=str(trame[i]) 
    self.taille= str(int(ll, 16)) 
    return self.taille  

  def determine_id(self, trame): 
    i=""
    for j in range(18, 20): 
      i+= trame[j]
    self.id= i
    return "0x"+i 

  def determine_flags(self, trame): 
    f= str(trame[20])[0]
    t= "0x"+str(trame[20])
    f= bin(int(f, 16))[2:].zfill(len(f)*4) #ignonrer "0b" puis en utilisant zfill recuperer la valeure sur 4 bits 
    self.flag["R"]= f[0]
    self.flag["DF"]= f[1]
    self.flag["MF"]=  f[2]
    return t 

  def analyse_flag(self, dflags): 
    ch="premier bit reserve a 0 \n"
    # Analyse DF 
    if dflags["DF"]==0: 
      ch+="DF = 0 fragmentation possible\n"
    else: 
      #DF=1 
      ch+="DF=1 fragmentation non autorise\n"
    #ANALYSE MF
    if dflags["MF"]==0:
      ch+="MF=0  il ne y a pas de fragment suivant le fragment courant"
    else: 
      #MF=1 
      ch+="MF=1 il y a un fragment suivant le fragment courant"
    return ch 


  def determine_fragment_offset(self, trame): 
    f= "".join(trame[20:22]) #Recuperer le champ fragment offset de la trame 
    self.fo= bin(int(f, 16))[2:].zfill(len(f)*4)[3:] #Recuperer le 13 bits de poids faible appatenant au fragment offset car les 3 premiers appartiennent au flag 
    return self.fo
  
  def ttl(self, trame):
    t=str(trame[22])                       
    self.TTL= int(t,  16)  
    return self.TTL 

  def determine_protocole(self, trame): 
    prot= {"01": "ICMP", "06": "TCP", "11": "UDP"}
    #Recuperer le protocole 
    p= str(trame[23])
    if p in prot: 
      self.protocole= prot[p]
      return (p, prot[p])

  def determine_checksum(self, trame):
    t= "".join(trame[24:26])
    self.header_checksum=t
    return t 
    

  def ip_src(self, trame): 
    s=""
    for i in range(26, 30):
      if i!=29: 
        s+= str(int(str(trame[i]), 16))
        s+="."
      else: 
         s+= str(int(str(trame[i]), 16))
    self.ipsrc=s 
    return self.ipsrc
  
  def ip_dest(self, trame): 
    d=""
    for i in range(30, 34): 
      if i!=33: 
        d+= str(int(str(trame[i]), 16))
        d+="."
      else:
         d+= str(int(str(trame[i]), 16))
    self.ipdest=d 
    return self.ipdest     


  def determine_option(self, trame): 
    dtype={ "0": "EOOL", "1":"NOP", "7":"RR", "68":"TS", "131":"LSR", "137":"SSR"} #Options possibles en decimale 
    #Determiner le type: 
    t= int(trame[34], 16) #Convertir en decimale 
    if t in dtype: 
      self.option= dtype[t] 

  def determine_option_length(self, trame):
    ihl= self.determine_ihl(trame) 
    self.option_length= ( ihl*4 ) - 20 #20 octets sans options donc taille option = taille entete - 20 
    return self.option_length