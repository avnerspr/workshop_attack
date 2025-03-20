from socket import socket, AF_INET, SOCK_STREAM


class Connection:

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.conn = socket(AF_INET, SOCK_STREAM)

    @classmethod
    def create_from_socket(cls, sock: socket) -> "Connection":
        ans = Connection(*sock.getpeername())
        ans.conn = sock
        return ans

    def send(self, data: bytes):
        """send the bytes over socket"""
        self.conn.sendall(data)

    def recv(self, size: int) -> bytes:
        ans = b""
        while len(ans) < size:
            ans += self.conn.recv(size - len(ans))

        return ans

    def send_msg(self, msg: bytes):
        """send with the legnth at the start"""
        self.send(int.to_bytes(len(msg), 4, "big"))
        self.send(msg)

    def recv_msg(self) -> bytes:
        """recv with the legnth at the start"""
        length = int.from_bytes(self.recv(4), "big")
        return self.recv(length)

    def connect(self):
        self.conn.connect((self.host, self.port))

    def start(self) -> bool:
        pass

    def close(self):
        self.conn.close()
