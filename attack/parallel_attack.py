from attacker import Attacker
from multiserver_attacker import MultiServerAttacker
from multiprocessing import Process, Pool
from icecream import ic
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Util.number import long_to_bytes, bytes_to_long
from LLL.lll import LLLWrapper
from pathlib import Path
from socket import SHUT_RDWR
from sage.all import matrix, ZZ


LLL = LLLWrapper(
    Path("attack/LLL/liblll.so")
)  # ! maybe should return a list[list[int]] instead of list[list[float]]
lll = LLL.lll


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


class ParallelAttacker:

    def __init__(
        self, N: int, E: int, ct: int, attacker_amount: int, host: str, ports: list[int]
    ) -> None:
        self.N = N
        self.E = E
        self.ct = ct
        self.host = host
        self.ports = ports
        self.attacker_count = attacker_amount

    def _split_into_k_lists(self, input_list: list, K: int):
        # Calculate the approximate size of each chunk
        avg_size = len(input_list) // K
        remainder = len(input_list) % K

        result = []
        start = 0

        for i in range(K):
            # Determine the end index for the current sublist
            end = start + avg_size + (1 if i < remainder else 0)
            result.append(input_list[start:end])
            start = end

        return result

    def attacker_warper(self, ports: list):
        ic("in attacker wrapper")
        ic(ports)
        attacker: Attacker = Attacker(
            self.N, self.E, self.ct, [self.host], ports, random_blinding=True
        )
        ic("created attacker")
        result = attacker.attack()
        return result

    def attack(self):
        """
        Attack the server using multiple attackers
        """
        with Pool(self.attacker_count) as pool:
            results = pool.map(
                self.attacker_warper,
                self._split_into_k_lists(self.ports, self.attacker_count),
            )

        ic("got results")
        # ic(results)

        range_list = []
        s_list = []

        for result in results:
            range_list.append(result[0])
            s_list.append(result[1])

        return self.conclusion(range_list, s_list)

    def conclusion(self, ranges: list[range], S: list[int]) -> int:
        """
        Conclusion of the attack, using the LLL algorithm to find the plaintext from the information gathered
        """
        v0 = S + [0]
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
        # ic(reduced_basis)
        for R in reduced_basis:
            # R = reduced_basis[-1]
            # # ic(R)
            for i in range(len(R) - 1):
                m = ((R[i] + vf[i]) * pow(S[i], -1, self.N)) % self.N
                ic(long_to_bytes(m))
        ic(R[-1] == -(self.N * (self.attacker_count - 1)) // self.attacker_count)
        return m


def vec_norm(vec: list[int]) -> int:
    """
    Return the norm of a vector
    """
    return sum(x * x for x in vec)


if __name__ == "__main__":
    HOSTS = ["localhost"] * 15
    PORTS = [8001 + i for i in range(15)]
    n, e = get_public()
    ic("got public")
    parallel = ParallelAttacker(n, e, get_cipher(), 3, HOSTS, PORTS)
    ic("created parallel attacker")
    parallel.attack()
    # m = matrix(ZZ, [[7, 2], [5, 3]])
    # res, t = ic(m.LLL(transformation = True))
    # ic(t * m)
