class Ethernet: 
  def __init__(self): 
    """Constructeur qui initialise les élements des la trame Etherne"""
    self.dest= "" 
    self.src="" 
    self.Et_type="" 

  def adresse_mac(self, trame, D_S):
    """Fonction qui retourne l'adresse Mac source ou destination d'une trame"""
    mac=""
    if D_S=="dest":  
      for i in range(6): 
        #Iterer sur les 6 octets pour récupérer l'adresse 
        if i!= 5: 
          #Affichage des : entre les octets 
          mac+= str(trame[i]) 
          mac+=":"
        else: 
          mac+= str(trame[i]) 
      self.dest=mac 
    else: 
      #il s'agit de l'adresse mac source 
      for i in range(6,12): 
        #Iterer sur les 6 octets pour récupérer l'adresse 
        if i!= 11: 
          #Affichage des : entre les octets 
          mac+= str(trame[i])
          mac+=":"
        else:
          mac+= str(trame[i]) 
      self.src=mac 

  def trame_type(self, trame):
    """Fonction qui trouve le type et sa difinition à partir d'un dictionnaire de types possibles"""
    Types={"0800":"IPv4","86dd": "Ipv6", "0805":"X.25","0806":"ARP","8035":"RARP"}
    t="" 
    for i in range(12,14): #Parcourir les 2 octets de type dans l'entete ethernet 
      t+=trame[i] #nous avons récupéré le type 
    if t in Types: #Trouvon s sa difinition 
      #Si le type dans la trame figure parmi les types du dictionnaire initialisé 
      return ("0x"+t, Types[t]) 
    else:
      return ("0x"+t, "Unknown type")