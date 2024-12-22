from typing import Tuple, Set, List
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from math import ceil, floor
from oracle import oracle, init_oracle
from icecream import ic

HOST = "localhost"
PORT = 8001


def get_public() -> Tuple[int, int]:
    with open("public_key.rsa", "rb") as key_file:
        pub_key = RSA.import_key(key_file.read())
    return pub_key.n, pub_key.e


def get_cipher() -> int:
    msg = b"hello_world"
    with open("public_key.rsa", "rb") as key_file:
        pub_key = RSA.import_key(key_file.read())
    cipher_rsa = PKCS1_v1_5.new(pub_key)

    return bytes_to_long(cipher_rsa.encrypt(b"hello world"))


def s_oracle(C: int, s: int) -> bool:
    return oracle(C * pow(s, E, N) % N, conn)


def blinding(C: int) -> Tuple[int, int]:
    ic("start blinding")
    for s0 in range(1, N):
        C0 = C * pow(s0, E, N) % N
        if oracle(C0, conn):
            return C0, s0


def find_next_conforming(C: int, start: int) -> int:
    for s in range(start, N):
        if s_oracle(C, s):
            return s


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
    for r_i in range(2 * ceil((b * s_list[-1] - 2 * B) / N), N):
        s_i = ceil((2 * B + r_i * N) / b)
        if s_i < (3 * B + r_i * N) / a:
            s_list.append(s_i)
            return s_i

    raise ValueError("the range of r search need to be bigger")


def update_intervals(M: Set[range], s_i: int) -> List[range]:
    M_res: List[range] = []
    for interval in M:
        a, b = interval.start, interval.stop - 1
        for r in range(((a * s_i - 3 * B + 1) // N), ((b * s_i - 2 * B) // N)):
            pos_sol_range = range(
                max(a, ceil((2 * B + r * N) / s_i)) % N,
                (min(b, (3 * B - 1 - r * N) // s_i) + 1) % N,
            )
            ic(pos_sol_range.stop - pos_sol_range.start)

            M_res.append(pos_sol_range)

    assert len(M_res) >= 1
    return M_res


def search(C: int, M: Set[range], s_list: List[int], iteration: int):
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


def algo_iteration(C: int, M: Set[range], s_list: List[int], iteration: int):
    ic(iteration)
    # step 2
    search(C, M, s_list, iteration)

    # step 3
    M = update_intervals(M, s_list[-1])

    # step 4
    if len(M) == 1:
        M_lst = list(M)
        if len(M_lst[0]) == 1:
            return M_lst[0][0] * pow(s_list[0], -1, N) % N  # found solution

    return False


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
    C0, s0 = ic(blinding(C))
    s_list = [s0]
    M: Set[range] = set([range(2 * B, 3 * B)])
    MAX_ITER = 1_000_000
    for iteration in range(1, MAX_ITER + 1):
        # steps 2-4
        res = algo_iteration(C0, M, s_list, iteration)
        if res:
            print(f"{res = }")
            break


if __name__ == "__main__":
    main()
