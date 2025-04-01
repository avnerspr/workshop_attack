from utils.attack_utils import search_start, search_mulitiple_intervals
from utils.rsa import check_padding_private_key
from attack.disjoint_segments import DisjointSegments
from Crypto.PublicKey import RSA
from random import randint
from typing import Any, Tuple, List
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.PublicKey.RSA import RsaKey

from eval_server.ctf_answers import level_2_answer, level_3_answer, level_4_answer


def ceil_div(x: int, y: int) -> int:
    return (x + y - 1) // y


BITS_LENGTH = 1024
E = 65537
B = 1 << (BITS_LENGTH - 16)


def string_to_DisjointSegments(M: str):
    return DisjointSegments.deserialize(M)


def blinding(N: int, E: int, C: int, key: RsaKey) -> Tuple[int, int]:
    for s0 in range(1, N):
        C0 = C * pow(s0, E, N) % N
        if check_padding_private_key(long_to_bytes(C0), key):
            return C0, s0


def search_single_interval(
    N: int, E: int, C: int, interval: range, s_list: list[int], B: int, key: RsaKey
):
    a, b = interval.start, interval.stop - 1
    for r_i in range(2 * ceil_div(b * s_list[-1] - 2 * B, N), N):
        s_i = ceil_div(2 * B + r_i * N, b)
        if s_i * a < (3 * B + r_i * N):
            if check_padding_private_key(long_to_bytes(C * pow(s_i, E) % N), key):
                s_list.append(s_i)
                return r_i, s_i

    raise ValueError("the range of r search needs to be bigger")


def update_intervals(
    N: int, prev_M: DisjointSegments, prev_s: int, B: int
) -> DisjointSegments:
    M_res = DisjointSegments()
    for interval in prev_M:
        a, b = interval.start, interval.stop - 1
        r_range = range(
            ((a * prev_s - 3 * B + 1) // N), ((b * prev_s - 2 * B) // N) + 1
        )
        for r in r_range:
            pos_sol_range = range(
                max(a, ceil_div(2 * B + r * N, prev_s)),
                (min(b, ((3 * B - 1 + r * N) // prev_s)) + 1),
            )

            M_res.add(pos_sol_range)

    assert len(M_res) >= 1
    return M_res


def outer_test_blinding(key: RsaKey, C: int):  # Challenge #1
    def test_blinding(s: str):
        try:
            s = int(s)
        except:
            return False, "Attempt failed. Incorrect value format"
        with_s = long_to_bytes(C * pow(s, key.e) % key.n)
        if check_padding_private_key(with_s, key):
            return (
                True,
                "You successfully solved level 1.",
            )
        else:
            return False, "Attempt failed. Incorrect blinding value"

    return test_blinding


def outer_test_level_2a(key: RsaKey, C0: int):  # Challenge #2
    def test_level_2a(s1):
        try:
            s1 = int(s1)
        except:
            return False, "Attempt failed. Incorrect value format"
        if s1 == level_2_answer:
            return (
                True,
                "You successfully solved level 2.",
            )

        else:
            return False, "Attempt failed. Incorrect value of s1"

    return test_level_2a


def outer_test_level_2b(
    key: RsaKey, C: int, M: DisjointSegments, prev_s: int
):  # Challenge #3
    # |M| > 1

    def test_level_2b(s):
        try:
            s = int(s)
        except:
            return False, "Attempt failed. Incorrect value format"
        if s == level_3_answer:
            return (
                True,
                "You successfully solved level 3.",
            )
        else:
            return False, "Attempt failed. Incorrect value of s"

    return test_level_2b


def outer_test_level_2c(
    key: RsaKey, C: int, M: DisjointSegments, prev_s: int, B
):  # Challenge #4
    # |M| == 1

    def test_level_2c(s):
        try:
            # r,s = r_s.split(",")
            # r, s = int(r), int(s)
            s = int(s)
        except:
            return False, "Attempt failed. Incorrect value format"

        # if (r, s) == search_single_interval(N,E,C,list(M)[0], [prev_s],B):
        if s == level_4_answer:
            return (
                True,
                "You successfully solved level 4.",
            )

        else:
            return False, "Attempt failed. Incorrect value of s"

    return test_level_2c


def outer_test_compute_M(
    key: RsaKey, C: int, prev_M: DisjointSegments, prev_s: int, B: int
):  # Challenge #5
    def test_compute_M(M: str):
        try:
            M = string_to_DisjointSegments(M)
        except:
            return False, "Attempt failed. Incorrect value format"

        if DisjointSegments.compare(M, update_intervals(key.n, prev_M, prev_s, B)):
            return (
                True,
                "You successfully solved level 5.",
            )
        else:
            return False, "Attempt failed. Incorrect value of M"

    return test_compute_M


def outer_test_final_level(message: int):  # Challenge #6
    def test_final_level(m: str):
        try:
            m = int(m)
        except:
            return False, "Attempt failed. Incorrect value format"

        if m == message:
            return (
                True,
                "You successfully solved level 6.",
            )
        else:
            return False, "Attempt failed. Incorrect value of m"

    return test_final_level
