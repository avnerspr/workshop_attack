from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from utils.connection import Connection
import socket
from Crypto.Util.number import bytes_to_long, getPrime, isPrime
from utils.rsa import check_padding, check_padding_private_key
import argparse
import multiprocessing
from time import sleep
import os
import signal


KEY_SIZE = 1024


def server_arguments_parser() -> argparse.Namespace:
    """
    Parses command-line arguments for the server.

    Returns:
        argparse.Namespace: Parsed arguments containing various configurations
        for the server, such as verbosity, thread count, port, timeout, and key generation.
    """
    parser = argparse.ArgumentParser(
        prog="server.py",
        description="Starts a multithreaded server that is vulnerable to the Bleichenbacher attack",
        epilog="Try running and see if you can decrypt the message",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="displays a message every 1000 messages to the server",
    )
    parser.add_argument("-c", "--count", help="number of threads to run, defaults to 5")
    parser.add_argument(
        "-k", "--keygen", action="store_true", help="make the server generate a new key"
    )
    parser.add_argument(
        "-t", "--timeout", help="sets the server's timeout defaults to 30 seconds"
    )
    parser.add_argument(
        "-p", "--port", help="sets the server's base port, defaults to 8001"
    )
    my_args = parser.parse_args()
    return my_args


def generate_key():
    """
    Generates a new RSA key pair (public and private keys) and saves them to disk.

    The keys are KEY_SIZE bits in size, and both private and public keys are saved in
    separate files: 'private_key.rsa' and 'public_key.rsa'.

    Returns:
        None
    """
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


def server_loop(
    s: socket.socket, port: int, cipher_rsa: PKCS1_v1_5.PKCS115_Cipher, verbose: bool
):
    """
    Handles incoming client connections and processes their messages.

    It listens for messages, checks the padding validity using RSA decryption,
    and sends a response back to the client. Optionally prints the server's progress
    every 10000 messages if verbosity is enabled.

    Args:
        s (socket): The server socket used to accept client connections.
        port (int): The port number the server is running on.
        cipher_rsa (PKCS1_v1_5.PKCS115_Cipher): RSA cipher object used to decrypt messages.
        verbose (bool): If True, prints the server's progress every 10000 messages.

    Returns:
        None
    """
    num_of_messages: int = 0

    while True:
        sock, addr = s.accept()
        conn = Connection.create_from_socket(sock)
        while True:
            try:
                data = conn.recv(KEY_SIZE // 8)
                # print(f"Got {bytes_to_long(data)} from {sock.getpeername()}")
                sleep(0.001)
                if not data:
                    print(f"server: {port} closed: {addr}")
                    break
                num_of_messages += 1
                correct_pad = check_padding(cipher_rsa, data, sentinel=None)
                # correct_pad = check_padding_private_key(data, cipher_rsa._key)
                if correct_pad:
                    conn.send(b"\x01" * 128)
                else:
                    conn.send(b"\x00" * 128)
                if verbose and (num_of_messages % 10000 == 0):
                    print(f"server: {port} got {num_of_messages} messages")
            except ConnectionError:
                print(f"server: {port} connection error: {addr}")
                break


def start_server(port: int, verbose: bool):
    """
    Initializes the server, generates or loads the RSA keys, and starts the server loop.

    Args:
        port (int): The port number the server will listen on.
        verbose (bool): If True, prints server progress every 10000 messages.

    Returns:
        None
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", port))

    with open("private_key.rsa", "rb") as f:
        key = RSA.import_key(f.read())

    private_key = key
    cipher_rsa = PKCS1_v1_5.new(private_key)

    s.listen()
    server_loop(s, port, cipher_rsa, verbose)


def stop_servers_after_delay(server_pids: list[int | None], delay: int):
    """
    Stops the server processes after a specified delay by sending SIGTERM signals.

    Args:
        server_pids (list[int]): List of process IDs for the running server processes.
        delay (int): The delay in seconds before stopping the servers.

    Returns:
        None
    """
    sleep(delay)

    for pid in server_pids:
        os.kill(pid, signal.SIGTERM)


def main(count: int, timeout: int, base_port: int):
    """
    Starts the specified number of servers in separate processes and stops them
    after the given timeout.

    Args:
        count (int): The number of server processes to start.
        timeout (int): The number of seconds before stopping the servers.
        base_port (int): The base port to start the servers on.

    Returns:
        None
    """
    with multiprocessing.Pool(count) as pool:
        server_pids = []

        for port in [base_port + i for i in range(count)]:
            result = pool.apply_async(
                start_server,
                args=(
                    port,
                    my_args.verbose,
                ),
            )

        servers = multiprocessing.active_children()
        server_pids = [server.pid for server in servers]
        stop_servers_after_delay(server_pids, timeout)


if __name__ == "__main__":
    my_args = server_arguments_parser()

    if my_args.keygen:
        generate_key()
        print("generated key")

    count: int = 5
    if my_args.count and my_args.count.isdecimal():
        count = int(my_args.count)

    timeout: int = 30
    if my_args.timeout and my_args.timeout.isdecimal():
        timeout = int(my_args.timeout)

    base_port: int = 8001
    if my_args.port and my_args.port.isdecimal():
        base_port = int(my_args.port)

    main(count, timeout, base_port)
