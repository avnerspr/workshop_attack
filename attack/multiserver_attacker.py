from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from oracle import oracle, init_oracle, KEY_SIZE, ServerClosed
from disjoint_segments import DisjointSegments
from random import randint
from icecream import ic
from concurrent.futures import ThreadPoolExecutor
from itertools import chain, count, islice, cycle
from typing import Iterator


def ceil_div(x: int, y: int) -> int:
    """
    This function is used to calculate the ceiling division of two numbers.
    """
    return (x + y - 1) // y


def batched(iterable, n):
    """Yield successive n-sized batches from the iterable."""
    it = iter(iterable)
    while batch := (islice(it, n)):  # Collect n items at a time
        yield batch


class Attacker:

    def __init__(
        self,
        N: int,
        E: int,
        ct: int,
        hosts: list[str] | str,
        ports: list[int] | int,
        thread_count: int = 1,
        random_blinding: bool = False,
        iteration: int = 1,
    ) -> None:
        self.N = N
        self.E = E
        self.ct = ct
        self.C = ct
        if thread_count == 1:
            if isinstance(hosts, str):
                self.hosts = [hosts]
            if isinstance(ports, int):
                self.ports = [ports]
        self.conns = [init_oracle(host, port) for host, port in zip(hosts, ports)]
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

    def oracle(self, num: int) -> bool:
        """
        This function is used to query the oracle with a number.
        the function passes in cycle on a number of servers to query the oracle with
        """
        return oracle(num, next(self.conn_cycler))

    def s_oracle(self, s: int) -> tuple[bool, int]:
        return self.oracle(self.C * pow(s, self.E, self.N) % self.N), s

    def blinding(self) -> tuple[int, int]:
        start = randint(1, self.N - 1) if self.random_blinding else 1
        s0 = self.find_next_conforming(start)
        self.s0 = s0
        self.s_list.append(s0)
        self.C = self.ct * pow(s0, self.E, self.N) % self.N
        return self.C, s0

    def find_next_conforming(self, start: int, chunk_size: int = 1000) -> int:
        return self.search_iterator(count(start), chunk_size)

    def search_iterator(self, iterator: Iterator, chunk_size: int = 1000) -> int:
        if self.iteration <= 10:
            with ThreadPoolExecutor(len(self.conns)) as executor:
                for batch in batched(iterator, chunk_size):
                    results = executor.map(self.s_oracle, batch)
                    for result, query in results:
                        if result:
                            executor.shutdown(cancel_futures=True)
                            return query
        else:
            for query in iterator:
                if self.s_oracle(query)[0]:
                    return query

        raise ValueError("Iterator search failed")

    def search_start(self, chunk_size=1000) -> int:
        """
        This function is used to search for the next s_i in the case where there are multiple intervals in M.
        """
        s_i = self.find_next_conforming(self.N // (3 * self.B) + 1, chunk_size)
        self.s_list.append(s_i)
        return s_i

    def search_mulitiple_intervals(self, chunk_size=1000) -> int:
        """
        This function is used to search for the next s_i in the case where there are multiple intervals in M.
        """
        s_i = self.find_next_conforming(self.s_list[-1] + 1, chunk_size)
        self.s_list.append(s_i)
        return s_i

    def search_single_interval(self, interval: range, chunk_size: int = 1000) -> int:
        """
        This function is used to search for the next s_i in the case where there is only one interval in M.
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

    def search(self) -> int:
        """
        This function is used to search for the next s_i.
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

    def update_intervals(self, s_i: int) -> DisjointSegments:
        """
        This function is used to update the intervals in M after finding the next s_i.
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

    def algo_iteration(self):
        """
        This function is used to run one iteration of the attack algorithm.
        """
        try:
            # step 2
            self.search()
        except ServerClosed:
            return True, self.M.smallest_inclusive()  # ran out of time

        # step 3
        self.update_intervals(self.s_list[-1])
        if self.iteration <= 5 or self.iteration % 50 == 0:
            ic(self.iteration)
            ic(self.M.size())

        # step 4
        if len(self.M) == 1:
            M_lst: list[range] = list(iter(self.M))
            if M_lst[0].stop - M_lst[0].start <= 1:
                answer = M_lst[0].start * pow(self.s_list[0], -1, self.N) % self.N
                return True, range(answer, answer + 1)  # found solution

        return False, self.M

    def attack(self) -> tuple[range, int]:
        ic("started attack")
        self.blinding()
        ic("did blinding")
        while True:
            res, ans = self.algo_iteration()
            if res:
                assert isinstance(ans, range)

                # result = ans
                # ans_num = result * pow(self.s0, -1, self.N) % self.N
                # ans = long_to_bytes(ans_num, KEY_SIZE // 8)
                # print(f"{ans = }")
                for conn in self.conns:
                    conn.close()
                return ans, self.s0
            self.iteration += 1


# ! only for testing
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


if __name__ == "__main__":
    HOSTS = ["localhost"] * 5
    PORTS = [8001, 8002, 8003, 8004, 8005]
    n, e = get_public()
    attacker = Attacker(n, e, get_cipher(), HOSTS, PORTS, 5, True)
    res_range, s0 = attacker.attack()
    res = res_range.start
    ic(res)
