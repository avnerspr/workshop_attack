from socket import socket, AF_INET, SOCK_STREAM, SO_REUSEADDR
from Crypto.Util.number import long_to_bytes, bytes_to_long

def init_oracle(host: str, port: int) -> socket:
    sock = socket(AF_INET, SOCK_STREAM)
    sock.connect((host, port))
    return sock

def oracle(num : int, sock: socket) -> bool:
    sock.send(long_to_bytes(num))
    data = sock.recv(1)

    return data[0] == 1
