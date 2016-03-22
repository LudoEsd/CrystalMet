# coding: utf8
#################################################################
#@Serveur Ddos                                                  #
#@auteur: Ludovic Chopin                                        #
#@commentaire: serveur Master Command et Control. Ce serveur    #
#effectue la sequence socket(), bind(), listen(), accept()      #                                           #        
#################################################################
import socket
 
PORT = 17834
HOTE = socket.gethostname()
TAILLE_FILE_ATTENTE = 10

#creation de la socket en streaming pour le TCP
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
#definitions des options de la socket
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#connection de la socket
s.bind(('',PORT))
#ecoute de la socket 
s.listen(TAILLE_FILE_ATTENTE)

print ('en ecoute...')

while True :
#accepte une connection venant du client
    source = s.accept()
    print ("Connexion avec"),source
#fermeture de la socket    
s.close()
    
