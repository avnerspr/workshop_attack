from eval_server import EvalServer


def test(answer: str):
    if answer == "right":
        return True, "That's great!"
    return False, "Net xoroshiy"


if __name__ == "__main__":
    server = EvalServer()
    server.add_test("test", test, {})
    server.run()
