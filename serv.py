#!/usr/bin/python
# coding: utf-8
# -*-coding:Latin-1 -*-
import socket
import os

URL = "127.0.0.1" # l'adresse d'écoute de votre serveur
port = 443      # le port d'écoute de votre serveur
#Création du serveur
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((URL,port))
server.listen(1)
#Connexion du client
cnx_client, cnx_info =server.accept() 
print cnx_info, "is connected"
cpt=1
#Ecoute du serveur
while cpt>0:
   msg = raw_input(">>")
   if len(msg)>0:
     #si "quit" on quitte
     if msg == "quit":
       cnx_client.send(msg)
       cpt=cpt-1   
     # si "&" on n'attend pas de retour
     if msg[:-1]=="&": 
       cnx_client.send(msg)
     else:
       #On envoie au client
       cnx_client.send(msg)
       #On reçoit le résultat de la part du client
       data = cnx_client.recv(4096)
       print data
server.close()