from typing import Tuple, Set, List
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from math import ceil, floor
from oracle import oracle, init_oracle
from disjoint_segments import DisjointSegments
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
    cipher_rsa = PKCS1_v1_5.new(pub_key, lambda n: b"\x01" * n) # TODO non deteministic

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
    for r_i in range(2 * ceil((b * s_list[-1] - 2 * B) / N), N):
        s_i = ceil((2 * B + r_i * N) / b)
        if s_i < (3 * B + r_i * N) / a:
            s_list.append(s_i)
            return s_i

    raise ValueError("the range of r search need to be bigger")


def update_intervals(M: DisjointSegments, s_i: int) -> List[range]:
    M_res = DisjointSegments()
    for interval in M:
        a, b = interval.start, interval.stop - 1
        for r in range(((a * s_i - 3 * B + 1) // N), ((b * s_i - 2 * B) // N) + 1):
            pos_sol_range = range(
                max(a, (2 * B + r * N) // s_i + 1),
                (min(b, (((3 * B - 1 + r * N) // s_i) + 1))),
            )
            # debug
            # db = [
            #     max(a, ceil((2 * B + r * N) / s_i)),
            #     (min(b, (((3 * B - 1 + r * N) // s_i) + 1))),
            #     N,
            # ]
            # db.sort()
            # ic(db)

            M_res.add(pos_sol_range)
            # ic(M_res)

    assert len(M_res) >= 1
    ic(M_res)
    ic(M_res.size())
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
    ic(iteration)
    # step 2
    search(C, M, s_list, iteration)
    ic(s_list[-1])

    # step 3
    M = update_intervals(M, s_list[-1])

    # step 4
    ic(len(M))
    if len(M) == 1:
        M_lst: list[range] = list(iter(M))
        if M_lst[0].stop - M_lst[0].start <= 1:
            return M_lst[0].start * pow(s_list[0], -1, N) % N  # found solution

    return False


def main():
    global N, E, K, B
    global conn
    conn = init_oracle(HOST, PORT)
    C = get_cipher()
    N, E = get_public()
    K = len(long_to_bytes(N))  # TODO better than this
    ic(K)
    B = pow(
        2, 8 * (K - 2)
    )  # the value of the lsb in the second most significant byte of N
    ic(B)
    C = C % N

    # step 1
    C0, s0 = ic(blinding(C))
    s_list = [s0]
    M: DisjointSegments = DisjointSegments([range(2 * B, 3 * B)])
    MAX_ITER = 1_000_000
    for iteration in range(1, MAX_ITER + 1):
        # steps 2-4
        res = algo_iteration(C0, M, s_list, iteration)
        if res:
            ans_num = res * pow(s0, -1, N) % N
            ans = long_to_bytes(ans_num, 64)
            print(f"{ans = }")
            break


if __name__ == "__main__":
    main()
