from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from binascii import hexlify
import socket


def generate_key():
    key = RSA.generate(1024)
    private_data = key.export_key()
    public_data = key.public_key().export_key()

    with open("private_key.rsa", "wb") as f:
        f.write(private_data)
    with open("public_key.rsa", "wb") as f:
        f.write(public_data)


def start_server(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", port))

    with open("private_key.rsa", "rb") as f:
        key = RSA.import_key(f.read())

    private_key = key
    cipher_rsa = PKCS1_v1_5.new(private_key)

    s.listen()

    while True:
        conn, addr = s.accept()

        while True:
            try:
                data = conn.recv(1024 // 8)
                decrypted = cipher_rsa.decrypt(data, sentinel=None)

                if decrypted != None:
                    conn.send(1)
                else:
                    conn.send(0)
            except Exception:
                print(f"connection closed: {addr}")
                break


if __name__ == "__main__":
    start_server()