from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from binascii import hexlify
from connection import Connection
import socket
from icecream import ic
from Crypto.Util.number import bytes_to_long, getPrime, isPrime
from rsa import check_padding

KEY_SIZE = 1024


def generate_key():
    p = getPrime(KEY_SIZE // 2)
    q = getPrime(KEY_SIZE // 2)
    n = p * q
    e = 0x10001
    d = pow(e, -1, (p - 1) * (q - 1))
    key = RSA.construct((n, e, d, p, q))
    private_data = key.export_key()
    public_data = key.public_key().export_key()

    with open("private_key.rsa", "wb") as f:
        f.write(private_data)
    with open("public_key.rsa", "wb") as f:
        f.write(public_data)


def start_server(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", port))

    with open("private_key.rsa", "rb") as f:
        key = RSA.import_key(f.read())

    private_key = key
    cipher_rsa = PKCS1_v1_5.new(private_key)

    s.listen()

    while True:
        sock, addr = s.accept()
        conn = Connection.create_from_socket(sock)
        while True:
            try:
                data = conn.recv(KEY_SIZE // 8)
                correct_pad = check_padding(cipher_rsa, data, sentinel=None)
                if correct_pad:
                    conn.send(b"\x01")
                else:
                    conn.send(b"\x00")
            except ConnectionResetError:
                print(f"connection closed: {addr}")
                break


if __name__ == "__main__":
    generate_key()
    print("key genarated")
    start_server(8001)
