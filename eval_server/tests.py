from rsa import check_padding
from attack.bleichenbacher import (
    search_mulitiple_intervals,
    ceil_div,
    search_single_interval,
    search_start,
    blinding,
)
from attack.disjoint_segments import DisjointSegments
from Crypto.PublicKey import RSA
from random import randint
from typing import Any, Tuple
from Crypto.Util.number import long_to_bytes


BITS_LENGTH = 1024
E = 65537
CONST_MESSAGE_1 = randint(0, 1 << BITS_LENGTH - 1)
CONST_MESSAGE_2 = randint(0, 1 << BITS_LENGTH - 1)
CONST_MESSAGE_3 = randint(0, 1 << BITS_LENGTH - 1)
CONST_MESSAGE_4 = randint(0, 1 << BITS_LENGTH - 1)
CONST_MESSAGE_5 = randint(0, 1 << BITS_LENGTH - 1)
CONST_MESSAGE_6 = randint(0, 1 << BITS_LENGTH - 1)

PRIVATE_KEY_1 = RSA.generate(BITS_LENGTH)
PRIVATE_KEY_2 = RSA.generate(BITS_LENGTH)
PRIVATE_KEY_3 = RSA.generate(BITS_LENGTH)
PRIVATE_KEY_4 = RSA.generate(BITS_LENGTH)
PRIVATE_KEY_5 = RSA.generate(BITS_LENGTH)
PRIVATE_KEY_6 = RSA.generate(BITS_LENGTH)

print(PRIVATE_KEY_3.e)


def string_to_DisjointSegments(M: str):
    return DisjointSegments.deserialize(M)


def get_NEC(key: RSA.RsaKey, m):
    return key.n, key.e, pow(m, key.d, key.n)


def blinding(N: int, E: int, C: int) -> Tuple[int, int]:
    for s0 in range(1, N):
        C0 = C * pow(s0, E, N) % N
        if check_padding(C0):
            return C0, s0


def search_single_interval(
    N: int, E: int, C: int, interval: range, s_list: list[int], B: int
):
    a, b = interval.start, interval.stop - 1
    for r_i in range(2 * ceil_div(b * s_list[-1] - 2 * B, N), N):
        s_i = ceil_div(2 * B + r_i * N, b)
        if s_i * a < (3 * B + r_i * N):
            if check_padding(C * pow(s_i, E) % N):
                s_list.append(s_i)
                return r_i, s_i

    raise ValueError("the range of r search need to be bigger")


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


def outer_test_blinding(N: int, E: int, C: int):  # Challenge #1
    def test_blinding(s: str):
        try:
            s = int(s)
        except:
            return False, "Attempt failed. Incorrect value format"
        if check_padding(C * pow(s, E) % N):
            return (
                True,
                'You successfully solved level 1. The flag for the next level is "secret_flag_3Kf03JF2hmfc3IxM"',
            )
        else:
            return False, "Attempt failed. Incorrect blinding value"

    return test_blinding


def generate_params_blinding(key: RSA.RsaKey) -> dict[str, Any]:
    m = CONST_MESSAGE_1
    N, E, C = get_NEC(key, m)
    return {"N": str(N), "E": str(E), "C": str(C)}


def outer_test_level_2a(N: int, E: int, C0: int):  # Challenge #2
    def test_level_2a(s1):
        try:
            s1 = int(s1)
        except:
            return False, "Attempt failed. Incorrect value format"
        if s1 == search_start(C0, list()):
            return (
                True,
                'You successfully solved level 2. The flag for the next level is "secret_flag_G5kqD94kd0soFjZ1"',
            )

        else:
            return False, "Attempt failed. Incorrect value of s1"

    return test_level_2a


def generate_params_level_2a(key: RSA.RsaKey) -> dict[str, str]:
    m = CONST_MESSAGE_2
    N, E, C = get_NEC(key, m)
    C0, s0 = blinding(N, E, C)
    return {"N": str(N), "E": str(E), "C0": str(C0)}


def outer_test_level_2b(
    N: int, E: int, C: int, M: DisjointSegments, prev_s: int
):  # Challenge #3
    # |M| > 1

    def test_level_2b(s: str):
        try:
            s = int(s)
        except:
            return False, "Attempt failed. Incorrect value format"
        if s == search_mulitiple_intervals(C, [prev_s]):
            return (
                True,
                'You successfully solved level 3. The flag for the next level is "secret_flag_3nG9fL4ofpEj46vj"',
            )
        else:
            return False, "Attempt failed. Incorrect value of s"

    return test_level_2b


def generate_params_level_2b(key: RSA.RsaKey) -> dict[str, str]:
    m = CONST_MESSAGE_3
    N, E, C = get_NEC(key, m)
    K = len(long_to_bytes(N))  # TODO better than this
    B = pow(
        2, 8 * (K - 2)
    )  # the value of the lsb in the second most significant byte of N

    C0, s0 = blinding(N, E, C)
    # s_list = [s0]
    # M: DisjointSegments = DisjointSegments([range(2 * B, 3 * B)])
    # MAX_ITER = 1_000_000
    # for iteration in range(1, MAX_ITER + 1):
    #     # steps 2-4
    #     res, M = algo_iteration(C0, M, s_list, iteration)
    #     if res:
    #         assert isinstance(M, int)
    #         result = M
    #         ans_num = result * pow(s0, -1, N) % N
    #         ans = long_to_bytes(ans_num, KEY_SIZE // 8)
    #         print(f"{ans = }")
    #         break

    # update_intervals(N, prev_M, prev_s, B)


def outer_test_level_2c(
    N: int, E: int, C: int, M: DisjointSegments, prev_s: int, B
):  # Challenge #4
    # |M| == 1

    def test_level_2c(s: str):
        try:
            # r,s = r_s.split(",")
            # r, s = int(r), int(s)
            s = int(s)
        except:
            return False, "Attempt failed. Incorrect value format"

        # if (r, s) == search_single_interval(N,E,C,list(M)[0], [prev_s],B):
        if s == search_single_interval(N, E, C, list(M)[0], [prev_s], B)[1]:
            return (
                True,
                'You successfully solved level 4. The flag for the next level is "secret_flag_5Kfk19fqeJ61jsm3"',
            )

        else:
            return False, "Attempt failed. Incorrect value of r,s"

    return test_level_2c


def outer_test_compute_M(
    N: int, E: int, C: int, prev_M: DisjointSegments, prev_s: int, B: int
):  # Challenge #5
    def test_compute_M(M: str):
        try:
            M = string_to_DisjointSegments(M)
        except:
            return False, "Attempt failed. Incorrect value format"

        if M == update_intervals(N, prev_M, prev_s, B):
            return (
                True,
                'You successfully solved level 5. The flag for the next level is "secret_flag_o1q9cMf43kVl2a6x"',
            )
        else:
            return False, "Attempt failed. Incorrect value of M"

    return test_compute_M


def outer_test_level_final(message: int):  # Challenge #6
    def test_level_final(m: str):
        try:
            m = int(m)
        except:
            return False, "Attempt failed. Incorrect value format"

        if m == message:
            return (
                True,
                'You successfully solved level 6. The flag for the next level is "secret_flag_p0voqE4iUv0Q8t35"',
            )
        else:
            return False, "Attempt failed. Incorrect value of M"

    return test_level_final
