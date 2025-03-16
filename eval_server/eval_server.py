from typing import Callable


class Server:
    def add_test(self, name: str, tester: Callable[[str], bool], metadata: dict):
        pass
