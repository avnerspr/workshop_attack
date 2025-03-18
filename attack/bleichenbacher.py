from typing import Tuple, Set, List
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from math import ceil, floor
from oracle import oracle, init_oracle, KEY_SIZE
from disjoint_segments import DisjointSegments
from random import randint
from icecream import ic

HOST = "localhost"
PORT = 8001


def ceil_div(x: int, y: int) -> int:
    return (x + y - 1) // y

def get_public() -> Tuple[int, int]:
    with open("public_key.rsa", "rb") as key_file:
        pub_key = RSA.import_key(key_file.read())
    return pub_key.n, pub_key.e


def get_cipher() -> int:
    msg = b"hello_world"
    with open("public_key.rsa", "rb") as key_file:
        pub_key = RSA.import_key(key_file.read())
    cipher_rsa = PKCS1_v1_5.new(pub_key)

    return bytes_to_long(cipher_rsa.encrypt(msg))


def s_oracle(C: int, s: int) -> bool:
    return oracle(C * pow(s, E, N) % N, conn)


def blinding(C: int) -> Tuple[int, int]:
    ic("start blinding")
    for s0 in range(1, N):
        C0 = C * pow(s0, E, N) % N
        if oracle(C0, conn):
            return C0, s0


def find_next_conforming(C: int, start: int) -> int:
    ctr = 0
    for s in range(start, N):
        ctr += 1
        if s_oracle(C, s):
            return s
        if ctr % 10_000 == 0:
            ic(ctr)


def search_start(C: int, s_list: List[int]) -> int:
    s1 = find_next_conforming(C, N // (3 * B) + 1)
    s_list.append(s1)
    return s1


def search_mulitiple_intervals(C: int, s_list: List[int]) -> int:
    s_i = find_next_conforming(C, s_list[-1] + 1)
    s_list.append(s_i)
    return s_i


def search_single_interval(C: int, interval: range, s_list: List[int]):
    a, b = interval.start, interval.stop - 1
    for r_i in range(2 * ceil_div(b * s_list[-1] - 2 * B, N), N):
        s_i = ceil_div(2 * B + r_i * N, b)
        if s_i * a < (3 * B + r_i * N):
            if s_oracle(C, s_i):
                s_list.append(s_i)
                return s_i

    raise ValueError("the range of r search need to be bigger")


def update_intervals(M: DisjointSegments, s_i: int, iteration: int) -> DisjointSegments:
    M_res = DisjointSegments()
    for interval in M:
        a, b = interval.start, interval.stop - 1
        r_range = range(((a * s_i - 3 * B + 1) // N), ((b * s_i - 2 * B) // N) + 1)
        for r in r_range:
            pos_sol_range = range(
                max(a, ceil_div(2 * B + r * N, s_i)),
                (min(b, (((3 * B - 1 + r * N) // s_i))) + 1),
            )

            M_res.add(pos_sol_range)

    assert len(M_res) >= 1
    return M_res


def search(C: int, M: DisjointSegments, s_list: List[int], iteration: int):
    if iteration == 1:
        # step 2.a
        search_start(C, s_list)

    elif len(M) > 1:
        # step 2.b
        search_mulitiple_intervals(C, s_list)
    else:
        assert len(M) == 1
        # step 2.c
        search_single_interval(C, list(M)[0], s_list)


def algo_iteration(C: int, M: DisjointSegments, s_list: List[int], iteration: int):
    # step 2
    search(C, M, s_list, iteration)

    # step 3
    M = update_intervals(M, s_list[-1], iteration)
    if iteration <= 5 or iteration % 50  == 0:
        ic(iteration)
        ic(M.size())

    # step 4
    if len(M) == 1:
        M_lst: list[range] = list(iter(M))
        if M_lst[0].stop - M_lst[0].start <= 1:
            return True, M_lst[0].start * pow(s_list[0], -1, N) % N  # found solution

    return False, M


class Attack:
    pass

    def __init__(self, N: int, E: int, ct: int, host: str, port: int, random_blinding: bool=False, iteration: int = 1) -> None:
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
        self.M: DisjointSegments = DisjointSegments([range(2 * self.B, 3 * self.B)])
        self.iteration = iteration
        
    def oracle(self, num: int) -> bool:
        return oracle(num, self.conn)
    
    def s_oracle(self, s: int) -> bool:
        return self.oracle(self.C * pow(s, self.E, self.N) % self.N)
    
    def blinding(self) -> Tuple[int, int]:
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
        s_i = self.find_next_conforming(self.s_list[-1] + 1)
        self.s_list.append(s_i)
        return s_i


    def search_single_interval(self, interval: range):
        a, b = interval.start, interval.stop - 1
        for r_i in range(2 * ceil_div(b * self.s_list[-1] - 2 * self.B, self.N), self.N):
            s_i = ceil_div(2 * self.B + r_i * self.N, b)
            if s_i * a < (3 * self.B + r_i * self.N):
                if self.s_oracle(s_i):
                    self.s_list.append(s_i)
                    return s_i

        raise ValueError("the range of r search need to be bigger")
    
    def search(self):
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
        M_res = DisjointSegments()
        for interval in self.M:
            a, b = interval.start, interval.stop - 1
            r_range = range(((a * s_i - 3 * self.B + 1) // self.N), ((b * s_i - 2 * self.B) // self.N) + 1)
            for r in r_range:
                pos_sol_range = range(
                    max(a, ceil_div(2 * self.B + r * self.N, s_i)),
                    (min(b, (((3 * self.B - 1 + r * self.N) // s_i) + 1))),
                )

                M_res.add(pos_sol_range)

        assert len(M_res) >= 1
        self.M = M_res
        return M_res

    def algo_iteration(self):
        # step 2
        self.search()

        # step 3
        self.update_intervals(self.s_list[-1])
        if self.iteration <= 5 or self.iteration % 50  == 0:
            ic(self.iteration)
            ic(self.M.size())

        # step 4
        if len(self.M) == 1:
            M_lst: list[range] = list(iter(self.M))
            if M_lst[0].stop - M_lst[0].start <= 1:
                return True, M_lst[0].start * pow(self.s_list[0], -1, self.N) % self.N  # found solution

        return False, self.M
    
    
    def attack(self) -> bytes:
        self.blinding()
        while True:
            res, ans = self.algo_iteration()
            if res:
                assert isinstance(ans, int)
                result = ans
                ans_num = result * pow(self.s0, -1, self.N) % self.N
                ans = long_to_bytes(ans_num, KEY_SIZE // 8)
                print(f"{ans = }")
                return ans
            self.iteration += 1
        

# class ParellelAttacker:
    
    
    

def main():
    global N, E, K, B
    global conn
    conn = init_oracle(HOST, PORT)
    C = get_cipher()
    N, E = get_public()
    K = len(long_to_bytes(N))  # TODO better than this
    B = pow(
        2, 8 * (K - 2)
    )  # the value of the lsb in the second most significant byte of N
    C = C % N

    # step 1
    C0, s0 = blinding(C)
    s_list = [s0]
    M: DisjointSegments = DisjointSegments([range(2 * B, 3 * B)])
    MAX_ITER = 1_000_000
    for iteration in range(1, MAX_ITER + 1):
        # steps 2-4
        res, M = algo_iteration(C0, M, s_list, iteration)
        if res:
            assert isinstance(M, int)
            result = M
            ans_num = result * pow(s0, -1, N) % N
            ans = long_to_bytes(ans_num, KEY_SIZE // 8)
            print(f"{ans = }")
            break


if __name__ == "__main__":
    # main()
    n, e = get_public()
    attacker = Attack(n, e, get_cipher(), HOST, PORT)
    attacker.attack()
