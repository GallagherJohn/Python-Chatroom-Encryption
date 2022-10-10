import time
import socket
import threading
import hashlib
import itertools
import sys
from Crypto import Random
from Crypto.PublicKey import RSA


#loading menu
done = False
def menu():
    for c in itertools.cycle(['....','.......','..........','............']):
        if done:
            break
        sys.stdout.write('\rChecking Connection To Server'+c)
        sys.stdout.flush()
        time.sleep(0.1)

#Create Keys 
random_generator = Random.new().read
key = RSA.generate(1024,random_generator)
public = key.publickey().exportKey()
private = key.exportKey()

#has keys
hash_object = hashlib.sha1(public)
hex_digest = hash_object.hexdigest()

#Set Socket 
server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

#HSelect Host/Port
host = input("Server Address To Be Connected ---> ")
port = int(input("Port of The Server ---> "))
#Bind connection
server.connect((host, port))
# print start message
thread_load = threading.Thread(target = menu)
thread_load.start()

time.sleep(4)
done = True
# Encrypts Message using AES CTR 
def send(t,name,key):
    mess = raw_input(name + " : ")
    key = key[:16]
    # merege message to name 
    whole = name+" : "+mess

    
    EncMessage = message.new(key, message.MODE_CTR, counter=lambda : key)
    encMsg = EncMessage.encrypt(whole)
    #converting the encrypted message to HEXADECIMAL to readable
    encMsg = encMsg.encode("hex").upper()
    if encMsg != "":
        print ("ENCRYPTED MESSAGE TO SERVER-> "+encMsg)
    server.send(encMsg)
def recv(t,key):
    newmess = server.recv(1024)
    print ("\nENCRYPTED MESSAGE FROM SERVER-> " + newmess)
    key = key[:16]
    decoded = newmess.decode("hex")
    ideaDecrypt = message.new(key, message.MODE_CTR, counter=lambda: key)
    dMsg = ideaDecrypt.decrypt(decoded)
    print ("\n**New Message From Server**  " + time.ctime(time.time()) + " : " + dMsg + "\n")

while True:
    server.send(public)
    confirm = server.recv(1024)
    if confirm == "YES":
        server.send(hex_digest)

        #connected msg
        msg = server.recv(1024)
        enc = eval(msg)
        decrypt = key.decrypt(en)
        # hash
        enc_object = hashlib.sha1(decrypt)
        enc_digest = enc_object.hexdigest()

        print ("\n-----ENCRYPTED PUBLIC KEY AND SESSION KEY FROM SERVER-----")
        print (msg)
        print ("\n-----DECRYPTED SESSION KEY-----")
        print (en_digest)
        print ("\n-----HANDSHAKE COMPLETE-----\n")
        alais = raw_input("\nYour Name -> ")

        while True:
            thread_send = threading.Thread(target = send , args = ( "------ Sending Message ------ ",alais,en_digest))
            thread_recv = threading.Thread(target=recv,args=( "------Recieving Message------" ,en_digest))
            thread_send.start()
            thread_recv.start()

            thread_send.join()
            thread_recv.join()
            time.sleep(0.5)
        time.sleep(60)
        server.close()

