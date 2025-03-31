from eval_server.eval_server import EvalServer
from eval_server.tests import outer_test_blinding
from attack.bleichenbacher import get_public, get_cipher


def add_tests(server: EvalServer):
    N, E = get_public()
    C = get_cipher()
    blinding_tester = outer_test_blinding(N, E, C)
    server.add_test("blinding", blinding_tester, {})


def main():
    server = EvalServer()
    add_tests(server)
    server.run()


if __name__ == "__main__":
    main()
