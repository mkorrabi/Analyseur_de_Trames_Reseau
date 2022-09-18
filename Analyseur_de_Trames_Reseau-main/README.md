# Analyseur_de_Trames_Reseau

## Introduction:
  Dans ce projet on se propose d'analyser des trames de données capturé avec un logiciel de capture  Wireshark. Dans ce contexte, la liste de données suivante sera présentée :
		- Ethernet 
		- IP  
		- UDP 
		- DNS 
		- DHCP 


## Structure du Programme:

Classe Verif: Preparation de la liste contenant les octets de la trame 

Classe Ethernet: Décortiquer la trame pour extraire les mac address et le type 

Class IP: Trouver son début grâce a la trame Ethernet. La classe extrait toutes parties traités par Wireshark 

Class UDP: Contient l’objet UDP et les fonctions pour extraire tous les champs du protocole UDP 

Class DNS: Contient l’objet DNS et les fonctions pour extraire les differents champs. De plus, elle traite les compression label en utilisant une fonction récursive 

Class DHCP: Contient l’objet DHCP et toutes les fonction permettant d’extraire les champs nécessaires 

Class Main: Fait appel à toutes les classes et leurs fonctions afin de faire les analyses 
