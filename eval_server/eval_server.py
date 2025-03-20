"""Eval server module."""

import json
import socketserver
from typing import Callable, Dict, Any, Tuple
from dataclasses import dataclass
from connection import Connection
from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime
from Crypto.Random import get_random_bytes
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR
from subprocess import Popen
import sys
from threading import Lock


DEBUG = True


@dataclass
class TestCase:
    """Represents a test case with a validation function and associated metadata."""

    tester: Callable[[str], Tuple[bool, str]]
    params_generator: Callable[[RSA.RsaKey], dict[str, str]]
    metadata: Dict[str, Any]
    oracles_required: int = 1
    key_size: int = 1024


# @dataclass
# class IterativeTestCase(TestCase):
#     """Represents a test case that requires multiple answers to be evaluated."""

#     tester: Callable[[str], Tuple[bool, str]]  # Evaluates a single answer
#     evaluator: Callable[[str], Tuple[str]]  # Returns the next test to evaluate
#     metadata: Dict[str, Any]  # Additional data associated with the test
#     prevEvaluation: str = ""
#     current_index: int = 0


class EvalServer(socketserver.TCPServer, socketserver.ThreadingMixIn):
    """A server that evaluates player responses against registered test cases and stores results persistently."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 9999,
        db_file: str = "results.json",
        oracle_limit: int = 20,
    ) -> None:
        """Initializes the server, loading test cases and past results."""
        super().__init__((host, port), EvalRequestHandler)
        self.tests: Dict[str, TestCase] = {}
        self.results: Dict[str, Dict[str, bool]] = self.load_results(db_file)
        self.db_file: str = db_file
        self.host: str = host
        self.port: int = port
        self.oracle_limit: int = oracle_limit
        self.oracles: dict[int, Popen[bytes]] = {}
        self.lock = Lock()

    def add_test(
        self,
        name: str,
        tester: Callable[[str], Tuple[bool, str]],
        metadata: Dict[str, Any],
    ) -> None:
        """Registers a new test case with a given name, validation function, and metadata.

        Args:
            name (str): The unique name of the test.
            tester (Callable[[str], bool]): A function that evaluates the correctness of an answer.
            metadata (Dict[str, Any]): Additional data associated with the test.
        """
        self.tests[name] = TestCase(tester, metadata)

    # def add_iterative_test(
    #     self,
    #     name: str,
    #     tester: Callable[[str], Tuple[bool, str]],
    #     evaluator: Callable[[str], Tuple[str]],
    #     metadata: Dict[str, Any],
    # ) -> None:
    #     """Registers a new iterative test case with a given name, validation function, evaluator function, and metadata.

    #     Args:
    #         name (str): The unique name of the test.
    #         tester (Callable[[str], bool]): A function that evaluates the correctness of an answer.
    #         evaluator (Callable[[str], str]): A function that returns the next test to evaluate.
    #         metadata (Dict[str, Any]): Additional data associated with the test.
    #     """
    #     self.tests[name] = IterativeTestCase(tester, evaluator, metadata)

    def save_results(self) -> None:
        """Saves the current evaluation results to a file."""
        with open(self.db_file, "w") as f:
            json.dump(self.results, f)

    @staticmethod
    def load_results(db_file: str) -> Dict[str, Dict[str, bool]]:
        """Loads past evaluation results from a file."""
        try:
            with open(db_file, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def evaluate(self, player: str, test_name: str, answer: str) -> Dict[str, Any]:
        """Evaluates a player's answer against a registered test case, handling errors gracefully."""
        if test_name in self.tests:
            test_case: TestCase = self.tests[test_name]
            try:
                correct, message = test_case.tester(answer)
                self.results.setdefault(player, {})[test_name] = correct
                self.save_results()
                return {"test": test_name, "correct": correct, "message": message}
            except Exception as e:
                return {"test": test_name, "error": str(e)}
        return {"test": test_name, "error": "Test not found"}

    def run_oracles(
        self, test_name: str, ports: list[int]
    ) -> Dict[str, Any]:  # TODO, change this to get better params
        key_size: int = self.tests[test_name].key_size
        oracles_required: int = self.tests[test_name].oracles_required
        if self.oracle_count + oracles_required > self.oracle_limit:
            return {"error": "Oracle limit reached"}
        self.oracle_count += oracles_required

        key = generate_key(key_size)
        key_str = key.export_key().decode("utf-8")
        password = get_random_bytes(16).decode("utf-8")
        try:
            for _ in range(oracles_required):
                self._run_oracle(key_str, password, ports)
        except Exception as e:
            if DEBUG:
                raise e
            for port in ports:
                self.close_oracle(port)
            ports.clear()
            return {"error": "Could not run oracles. " + str(e)}

        public = key.public_key()
        public_str = public.export_key().decode("utf-8")
        return {"ports": ports, "public_key": public_str, "password": password}

    def close_oracle(self, port: int):
        if port not in self.oracles:
            return
        process = self.oracles[port]
        process.terminate()
        process.wait()
        del self.oracles[port]

    def _run_oracle(self, key: str, password: str, ports: list[int]) -> int:
        port = find_open_port()
        process = Popen([sys.executable, str(port), key, password])
        self.oracles[port] = process
        ports.append(port)

    def run(self) -> None:
        """Starts the server and listens for incoming player submissions, handling shutdown gracefully."""
        print(f"Server running on {self.host}:{self.port}")
        try:
            self.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server gracefully...")
            self.server_close()  # Closes the socket
            print("Server stopped.")

    def server_close(self) -> None:
        super().server_close()
        for port in self.oracles.keys():
            self.close_oracle(port)


def find_open_port() -> int:
    """Finds an available port for the game server."""
    with socket(AF_INET, SOCK_STREAM) as s:
        s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        s.bind(("", 0))  # Bind to any available port
        return s.getsockname()[1]  # Return assigned port


class EvalRequestHandler(socketserver.BaseRequestHandler):
    """Handles incoming player requests by evaluating their answers."""

    def handle(self) -> None:
        """Processes a player's request, evaluates their answer, and responds with the result."""
        assert isinstance(self.server, EvalServer)
        ports: list[int] = []
        try:
            with self.server.lock:
                self.conn = Connection.create_from_socket(self.request)
                data: bytes = self.conn.recv_msg()
                request: Dict[str, str] = json.loads(data.decode("utf-8"))
                test_name = request["test"]
                player_name = request["player"]
                params = self.server.run_oracles(request["test"], ports)
            params_json = json.dumps(params).encode("utf-8")
            self.conn.send_msg(params_json)

            answer = self.conn.recv_msg().decode("utf-8")
            if not answer:
                return
            response: Dict[str, Any] = self.server.evaluate(
                player_name, test_name, answer
            )
            self.conn.send_msg(json.dumps(response).encode("utf-8"))
        except (json.JSONDecodeError, KeyError):
            self.conn.send_msg(
                json.dumps({"error": "Invalid request format"}).encode("utf-8")
            )
        except Exception as e:
            if DEBUG:
                raise e
            else:
                self.conn.send_msg(json.dumps({"error": str(e)}).encode("utf-8"))
        finally:
            self.conn.close()
            for port in ports:
                self.server.close_oracle(port)


def generate_key(key_size: int = 1024) -> RSA.RsaKey:
    p = getPrime(key_size // 2)
    q = getPrime(key_size // 2)
    n = p * q
    e = 0x10001
    d = pow(e, -1, (p - 1) * (q - 1))
    key = RSA.construct((n, e, d, p, q))
    return key
