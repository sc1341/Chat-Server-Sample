#!/usr/bin/env python3 

import socket
import threading 
import sys 
import os
import base64 

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class CryptographyHandler:

    def __init__(self,password='p@ssw0rd'):
        self.kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt = b'\xab\x83\xfb\xb5\xe8\xd5\xf5\xd5\xd0\xbc\xe4\xbd\t2\xb3n',
            iterations=480000
        )
        self.key = base64.urlsafe_b64encode(self.kdf.derive(password.encode()))


    def encrypt(self, message : str):
        return Fernet(self.key).encrypt(message.encode())

    def decrypt(self, message: str): 
        return Fernet(self.key).decrypt(message.encode()) 

class Client: 

    def __init__(self, host, port):
        self.host = host
        self.port = port 
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((host, port))
        self.t = threading.Thread(target=self.handle_incoming_messages)
        self.exit_event = threading.Event()
        self.crypto = CryptographyHandler()
        self.t.start()
        self.handle_outgoing_messages()


    def handle_outgoing_messages(self):
        while True:
            msg = input(">> ")
            msg = self.crypto.encrypt(msg)
            if msg.lower() == "exit":
                self.s.close()
                self.exit_event.set()
                self.t.join()
                break
            self.s.sendall(msg)

    
    def handle_incoming_messages(self):
        while not self.exit_event.is_set():
            try:
                msg = self.s.recv(1024)
                from_address, cipher_text = msg.decode().split(']')[0], msg.decode().split(']')[1]
                decrypted_text = self.crypto.decrypt(cipher_text)
                message = f"{from_address}:{decrypted_text.decode()}"
                print(message)
                if not msg:
                    break
            except Exception as e: 
                print(e)



class Server:

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.clients = []
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind((self.host, self.port))
        self.s.listen(10)
        while True: 
            client, host = self.s.accept() 
            print(f"{host} connected to server")
            self.clients.append(client)
            t = threading.Thread(target=self.client_handler, args=(client, host,))
            t.start()

    def client_handler(self, client, host):
        """
        Handle the client connection for each client. This is run as a thread. 
            Parameters:
                client - a client socket object
                host - a tuple with the host and port
        """
        while True:
            message = client.recv(1024)
            print(f"Recieved {message} from {host}")
            for s in self.clients: 
                if s == client:
                    pass
                else:
                    remote_ip, remote_port = s.getpeername()
                    s.sendall(f'[From: {remote_ip}:{remote_port}]'.encode() + message)


def main():
    if len(sys.argv) < 4: 
        print("USAGE: python3 chat.py server/client host port")
        sys.exit()
    
    mode,host, port = sys.argv[1], sys.argv[2], sys.argv[3]
    if mode == "server":
        s = Server(host, int(port))
    
    elif mode == "client":
        c = Client(host, int(port))


if __name__ == '__main__':
    main()


