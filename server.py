from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from binascii import hexlify
from connection import Connection
import socket
from icecream import ic
from Crypto.Util.number import bytes_to_long, getPrime, isPrime
from rsa import check_padding
import threading
import argparse
from multiprocessing import Process, Pool


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


def start_server(port, verbose):
    num_of_messages: int = 0
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
                num_of_messages += 1
                correct_pad = check_padding(cipher_rsa, data, sentinel=None)
                if correct_pad:
                    conn.send(b"\x01")
                    # if verbose:
                    #     print(
                    #         f"server: {port} got the following PKCS conforming message {str(data)}"
                    #     )
                else:
                    conn.send(b"\x00")
                if verbose and (num_of_messages % 10000 == 0):
                    print(f"server: {port} got {num_of_messages} messages")
            except ConnectionResetError:
                print(f"connection closed: {addr}")
                break


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="server.py",
        description="Starts a multithreaded server that is vulnerable to the Bleichenbacher attack",
        epilog="Try running and see if you can decrypt the message",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="displays when a message is PKCS conforming",
    )
    parser.add_argument("-c", "--count", help="number of threads to run, defaults to 5")
    parser.add_argument(
        "-k", "--keygen", action="store_true", help="make the server generate a new key"
    )
    args = parser.parse_args()

    if args.keygen:
        generate_key()
        print("generated key")

    thread_list: list[threading.Thread] = []

    count = 5
    if args.count and args.count.isdecimal():
        count = int(args.count)

    with Pool(count) as pool:
        servers = pool.starmap(
            start_server, [(8001 + i, args.verbose) for i in range(count)]
        )
