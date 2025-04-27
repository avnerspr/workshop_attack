from typing import Any
import socket
import json

SERVER_ADDRESS = ("localhost", 8888)  # Replace with the actual server address and port


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
