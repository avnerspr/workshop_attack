from typing import Any
import socket
import json
from connection import Connection
from disjoint_segments import DisjointSegments

SERVER_ADDRESS = ("localhost", 9999)  # Replace with the actual server address and port


CURRENT_TEST_CONN = "test1"  # Replace with the current test name


class TestConnection(Connection):
    """
    A connection class for interacting with the test evaluation server.
    """

    def __init__(self, test_name: str, player_name: str):
        """
        Initializes the connection with the server and sends the test and player names.

        Args:
            test_name (str): The name of the test.
            player_name (str): The name of the player.
        """
        super().__init__(SERVER_ADDRESS[0], SERVER_ADDRESS[1])
        self.test_name = test_name
        self.player_name = player_name

    def start(self):
        self.connect()
        self.send_msg(
            json.dumps({"test": self.test_name, "player": self.player_name}).encode(
                "utf-8"
            )
        )
        params = json.loads(self.recv_msg().decode("utf-8"))
        public_key 
        if "error" in params:
            self.close()
            raise ValueError(f"error in server: {params["error"]}")
        self.params = params

    def send_answer(self, answer: Any) -> dict[str, Any]:
        """
        Sends an answer to the server and receives the evaluation results.

        Args:
            answer (Any): The answer to the test question.

        Returns:
            A dictionary containing the evaluation results.
        """
        try:
            text = ""
            if isinstance(answer, str):
                text = answer
            elif isinstance(answer, int):
                text = str(answer)
            elif isinstance(answer, DisjointSegments):
                text = answer.serialize()
            if not text:
                return {
                    "error": "Invalid answer type, answer must be a string, integer or DisjointSegments object"
                }
            self.send_msg(text.encode("utf-8"))
            response = self.recv_msg()
            return json.loads(response.decode("utf-8"))
        except Exception as e:
            return {"error": f"An error occurred: {e}"}


def send_answer(player_name: str, test_name: str, answer: Any) -> dict:
    """
    Sends an answer to the TCP JSON test evaluation server.

    Args:
        player_name: The name/ID of the player.
        test_name: The name of the test being answered.
        answer: The answer provided by the player.

    Returns:
        A dictionary representing the server's JSON response.
        Returns an empty dictionary if a connection error occurs.
    """
    try:
        answer = str(answer)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect(SERVER_ADDRESS)

            request_data = {"player": player_name, "test": test_name, "answer": answer}
            json_request = json.dumps(request_data)
            client_socket.sendall(json_request.encode("utf-8"))

            response_data = b""
            while True:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                response_data += chunk

            if not response_data:
                return {"error": "No response from server"}

            response_json = json.loads(response_data.decode("utf-8"))
            return response_json

    except Exception as e:
        return {"error": f"An error occurred: {e}"}


