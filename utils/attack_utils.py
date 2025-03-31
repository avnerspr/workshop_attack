from typing import List
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Util.number import long_to_bytes
from utils.rsa import check_padding_private_key


def s_oracle(C: int, s: int, key: RsaKey) -> bool:
    ct = C * pow(s, key.e, key.n) % key.n
    return check_padding_private_key(long_to_bytes(ct), key)


def find_next_conforming(C: int, start: int, key: RsaKey) -> int:
    ctr = 0
    for s in range(start, key.n):
        ctr += 1
        if s_oracle(C, s, key):
            return s


def search_start(C: int, s_list: List[int], key: RsaKey) -> int:
    K = len(long_to_bytes(key.n))
    B = pow(
        2, 8 * (K - 2)
    )  # the value of the lsb in the second most significant byte of N

    s1 = find_next_conforming(C, key.n // (3 * B) + 1, key)
    s_list.append(s1)
    return s1


def search_mulitiple_intervals(C: int, s_list: List[int], key: RsaKey) -> int:
    s_i = find_next_conforming(C, s_list[-1] + 1, key)
    s_list.append(s_i)
    return s_i
