"""Eval server module."""

import json
import traceback
import socketserver
from typing import Callable, Dict, Any, Tuple
from dataclasses import dataclass


@dataclass
class TestCase:
    """Represents a test case with a validation function and associated metadata."""

    tester: Callable[[str], Tuple[bool, str]]
    metadata: Dict[str, Any]


class EvalServer(socketserver.TCPServer):
    """A server that evaluates player responses against registered test cases and stores results persistently."""

    def __init__(
        self, host: str = "0.0.0.0", port: int = 9999, db_file: str = "results.json"
    ) -> None:
        """Initializes the server, loading test cases and past results."""
        super().__init__((host, port), EvalRequestHandler)
        self.tests: Dict[str, TestCase] = {}
        self.results: Dict[str, Dict[str, bool]] = self.load_results(db_file)
        self.db_file: str = db_file
        self.host: str = host
        self.port: int = port

    def add_test(self, name: str, test: TestCase) -> None:
        """Registers a new test case with a given name, validation function, and metadata.

        Args:
            name (str): The unique name of the test.
            tester (Callable[[str], bool]): A function that evaluates the correctness of an answer.
            metadata (Dict[str, Any]): Additional data associated with the test.
        """
        self.tests[name] = test

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
                traceback.print_exc()
                return {"test": test_name, "error": str(e)}
        return {"test": test_name, "error": "Test not found"}

    def run(self) -> None:
        """Starts the server and listens for incoming player submissions, handling shutdown gracefully."""
        print(f"Server running on {self.host}:{self.port}")
        try:
            self.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server gracefully...")
            self.server_close()  # Closes the socket
            print("Server stopped.")


class EvalRequestHandler(socketserver.BaseRequestHandler):
    """Handles incoming player requests by evaluating their answers."""

    def handle(self) -> None:
        """Processes a player's request, evaluates their answer, and responds with the result."""
        data: bytes = self.request.recv(1024).strip()
        try:
            request: Dict[str, str] = json.loads(data.decode("utf-8"))
            assert isinstance(self.server, EvalServer)
            response: Dict[str, Any] = self.server.evaluate(
                request["player"], request["test"], request["answer"]
            )
        except (json.JSONDecodeError, KeyError):
            response = {"error": "Invalid request format"}
        self.request.sendall(json.dumps(response).encode("utf-8"))


def main():
    eval_server = EvalServer()
    eval_server.add_test()


if __name__ == "__main__":
    main()
