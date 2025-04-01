from Crypto.Util.number import bytes_to_long, long_to_bytes
import eval_server.ctf_params as ctf_params
from eval_server.ctf_answers import level_6_answer

import eval_server.tests as tests
from eval_server.eval_server import EvalServer, TestCase

from argparse import ArgumentParser, Namespace

from Crypto.PublicKey.RSA import import_key, RsaKey


def get_arguments() -> Namespace:
    parser = ArgumentParser(
        prog="CTF Challenge Evaluation Server",
        description="Run this to open a port for players to send their CTF answers to.",
    )

    parser.add_argument(
        "-p", "--port", help="The port to run the server on", default=9999
    )
    parser.add_argument(
        "--host", help="The host to run the server on", default="localhost"
    )

    return parser.parse_args()


def add_tests(server: EvalServer, key: RsaKey):
    B = pow(2, 8 * (len(long_to_bytes(key.n)) - 2))

    blinding_test = tests.outer_test_blinding(key, ctf_params.level_1_C)
    server.add_test(
        ctf_params.level_1_name,
        TestCase(blinding_test, {"score": ctf_params.level_1_score}),
    )

    twoA_test = tests.outer_test_level_2a(key, ctf_params.level_2_C0)
    server.add_test(
        ctf_params.level_2_name,
        TestCase(twoA_test, {"score": ctf_params.level_2_score}),
    )

    twoB_test = tests.outer_test_level_2b(
        key, ctf_params.level_3_C, ctf_params.level_3_M, ctf_params.level_3_prev_s
    )
    server.add_test(
        ctf_params.level_3_name,
        TestCase(twoB_test, {"score": ctf_params.level_3_score}),
    )

    twoC_test = tests.outer_test_level_2c(
        key, ctf_params.level_4_C, ctf_params.level_4_M, ctf_params.level_4_prev_s, B
    )
    server.add_test(
        ctf_params.level_4_name,
        TestCase(twoC_test, {"score": ctf_params.level_4_score}),
    )

    level5_test = tests.outer_test_compute_M(
        key,
        ctf_params.level_5_C,
        ctf_params.level_5_prev_M,
        ctf_params.level_5_prev_s,
        B,
    )
    server.add_test(
        ctf_params.level_5_name,
        TestCase(level5_test, {"score": ctf_params.level_5_score}),
    )

    level6_test = tests.outer_test_final_level(level_6_answer)
    server.add_test(
        ctf_params.level_6_name,
        TestCase(level6_test, {"score": ctf_params.level_6_score}),
    )


def main():
    args = get_arguments()
    server = EvalServer(args.host, int(args.port))

    with open("private_key.rsa") as file:
        key = import_key(file.read())
    add_tests(server, key)
    server.run()


if __name__ == "__main__":
    main()
