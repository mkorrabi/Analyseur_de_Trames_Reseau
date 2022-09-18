class verif:
  def __init__(self, no_fic):
    self.fic=no_fic
    self.liste=[]

  def fic_to_liste(self, file):#Lecture ligne par ligne du fichier 
    l=[]
    for i in file:
      l.append(i)
    return l 

  def ouverture(self):
    try: 
      file=open(self.fic, "r")

      liste= self.fic_to_liste(file)#Liste representat le fichier passé en argument
            
      # Vérifier les offsets 
      b= self.verif_offset(liste) #Booleen true or false 
      if not(b):
        raise Exception("Erreur d'offset")
      else: #On a le bo offset 
        # Donc on enleve les commentaire de la liste 
        # Enlever les offsets vu qu'ils sont tous bon 
        liste= self.skip_offset(liste) #On a une liste sans les offsets 
              
        # Enlever les espaces 
        liste= self.enlever_espace(liste)
        l= self.enlever_commentaires(liste)
        return l #Renvoyer la liste des octets 
    except: 
      print("Erreure ouverture du fichier")


  def enlever_espace(self, liste):
    l=[]
    for i in liste:
      l.append(i.replace(" ", "")) 
    return l 

  def verif_offset(self, liste):
    loff=[]
    for i in range(len(liste)):
      loff.append(int(liste[i][:4], 16))
    soff= loff.sort() #Sort les offset  
    if soff!=loff:
      False
    return  True 
  
  def skip_offset(self, l_originale):
    l=[]
    for i in l_originale:
      l.append(i[4:])
    return l 


  def is_hex(self, oct):
    try: 
      h=int(oct, 16) #Convertir en decimale 
      return True #Valeure hexa 
    except: 
      return False #Valeure non hexa

  def enlever_commentaires(self, liste):
    l=[]
    for j in liste: 
      for i in range(0, len(j), 2):
        # pas de 2 pour recuperer les octets
        if i<len(j)-1:
          o= j[i]+j[i+1]
          # Verification que c'est un octet 
          if self.is_hex(o): 
            l.append(j[i]+j[i+1])
          else: 
            break 
    return l 
