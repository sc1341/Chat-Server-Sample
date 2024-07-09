

# [From: 192.168.16.138:50244]gAAAAABmjYiNBwh0vg0ZN0xFEngvzLxggzw2PHuOIbeyO5xw1fCcsafw1xzROBkhr_F-lUF7iBuqcz7V0VXzQV7RCWSO2S6_mg== - sample output

import base64

from scapy.all import sniff, TCP, IP, Raw
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



def packet_callback(packet):

    if packet.haslayer(TCP) and packet.haslayer(Raw):
        raw_payload = packet[Raw].load
        
        try:
            payload_str = raw_payload.decode('utf-8')
            if "[From:" in payload_str:
                print(f"Packet from {packet[IP].src} to {packet[IP].dst}:")
                print(payload_str)
                _, host, port = payload_str.split(':')
                host = host.strip() 
                encrypted_payload = payload_str.split(']')[1] 
                decrypted_payload = CryptographyHandler().decrypt(encrypted_payload)
                print(f"Decrypted payload: {decrypted_payload}")

        except UnicodeDecodeError:
            pass

def main():
    bpf_filter = "tcp"
    print("Starting to capture TCP packets containing '[From:'...")
    sniff(filter=bpf_filter, prn=packet_callback, store=False)

if __name__ == "__main__":
    main()

