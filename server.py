#!/usr/bin/env python3 

import socket
import threading 


class Server:

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.clients = []
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind((self.host, self.port))
        self.s.listen(5)
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
    s = Server('localhost', 1234)


if __name__ == '__main__':
    main()


