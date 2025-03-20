from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from connection import Connection
import socket
from icecream import ic
from Crypto.Util.number import bytes_to_long, getPrime, isPrime
from rsa import check_padding
import argparse
import multiprocessing
from time import sleep
import os
import signal


KEY_SIZE = 1024


def parse_server_arguments():
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
    my_args = parser.parse_args()
    return my_args


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


def start_server(port: int, verbose: bool):
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
                sleep(0.001)
                if not data:
                    print(f"server: {port} closed: {addr}")
                    break
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
            except ConnectionError:
                print(f"server: {port} connection error: {addr}")
                break


def stop_servers_after_delay(server_pids: list[int], delay: int):
    sleep(delay)  # Wait for X seconds before killing the processes

    # Kill each worker process using the PID
    for pid in server_pids:
        os.kill(pid, signal.SIGTERM)  # Gracefully terminate the process


if __name__ == "__main__":
    my_args = parse_server_arguments()

    if my_args.keygen:
        generate_key()
        print("generated key")

    count = 5
    if my_args.count and my_args.count.isdecimal():
        count = int(my_args.count)

    with multiprocessing.Pool(count) as pool:
        server_pids = []

        # servers = pool.starmap(
        #     start_server, [(8001 + i, my_args.verbose) for i in range(count)]
        # )

        for port in [8001 + i for i in range(count)]:
            result = pool.apply_async(
                start_server,
                args=(
                    port,
                    my_args.verbose,
                ),
            )

        servers = multiprocessing.active_children()
        server_pids = [server.pid for server in servers]
        stop_servers_after_delay(server_pids, 60)
