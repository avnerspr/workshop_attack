import eval_server.tests as tests
from eval_server.eval_server import EvalServer, TestCase
from attack.create_attack_config import get_cipher, get_public

from typing import Callable, Dict, Any, Tuple
from argparse import ArgumentParser, Namespace


def get_arguments() -> Namespace:
    parser = ArgumentParser(
        prog="CTF Challenge Evaluation Server",
        description="Run this to open a port for players to send their CTF answers to.",
    )

    parser.add_argument("-p", "--port", help="The port to run the server on")
    parser.add_argument("--host", help="The host to run the server on")

    return parser.parse_args()


def main():
    args = get_arguments()
    server = EvalServer(args.host, int(args.port))

    N, E = get_public()
    message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Praesent pharetra orci ac nisi auctor."
    C = get_cipher(message)
    blinding_test = tests.outer_test_blinding(N, E, C)
    server.add_test("blinding", TestCase(blinding_test, {}))
    server.run()


if __name__ == "__main__":
    main()
