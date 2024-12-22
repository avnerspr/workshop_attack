from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from binascii import hexlify
import socket

def start_server(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)		 
    s.bind(('', port))

    key = RSA.generate(1024)
    private_key = key
    public_key = key.publickey()
    cipher_rsa = PKCS1_v1_5.new(private_key)

    print(f"public key is: {public_key}")

    s.listen()	 

    while True: 
        conn, addr = s.accept()	 

        while True:
            try:
                data = conn.recv(1024 // 8)
                decrypted = cipher_rsa.decrypt(data, sentinel=None)

                if(decrypted != None):
                    conn.send(1)
                else:
                    conn.send(0)
            except Exception:
                print(f"connection closed: {addr}")
                break
