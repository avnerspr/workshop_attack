from socket import socket, AF_INET, SOCK_STREAM, SO_REUSEADDR
from Crypto.Util.number import long_to_bytes, bytes_to_long
from icecream import ic

KEY_SIZE = 512


def init_oracle(host: str, port: int) -> socket:
    sock = socket(AF_INET, SOCK_STREAM)
    sock.connect((host, port))
    return sock


def oracle(num: int, sock: socket) -> bool:
    sendme = long_to_bytes(num, KEY_SIZE // 8)
    assert len(sendme) == (KEY_SIZE // 8)
    sock.sendall(sendme)
    data = sock.recv(1)

    return data[0] == 1
