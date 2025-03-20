from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
import threading
from threading import Thread


class Listener:
    def __init__(self, host="localhost", port=8080, backlog=1000):
        """
        Initialize the listener with a host and port.
        """
        self.host = host
        self.port = port
        self.backlog = backlog
        self.server_socket: socket | None = None
        self.active_connection: list[Thread] = []

    def start(self):
        """
        Start the listener to accept incoming client connections.
        """
        # Step 1: Create a socket object for the server
        self.server_socket = socket(AF_INET, SOCK_STREAM)
        self.server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        # Step 2: Bind the server to the given host and port
        self.server_socket.bind((self.host, self.port))
        # Step 3: Start listening for incoming connections
        self.server_socket.listen(self.backlog)

        while True:
            # Step 4: Accept incoming connections
            conn, _ = self.server_socket.accept()
            # for each accepted connection create an Handler Instace to handle it, run the handler in a separate thread
            handler = Handler(conn)
            thread = Thread(target=handler.handle_forever)
            self.active_connection.append(thread)
            thread.start()

    def stop(self):
        """
        Stop the listener and close the server socket.
        """
        pass


if __name__ == "__main__":
    listener = Listener(host="localhost", port=9003)
    listener.start()
