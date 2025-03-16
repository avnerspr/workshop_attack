from attacker import Attacker
from multiprocessing import Process, Pool
from icecream import ic
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Util.number import long_to_bytes, bytes_to_long


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


class ParllelAttacker:

    def __init__(self, N: int, E: int, ct: int, host: str, ports: list[int]) -> None:
        self.N = N
        self.E = E
        self.ct = ct
        self.attacker_count = len(ports)
        self.host = host
        self.ports = ports

    def attacker_warper(self, port):
        ic("in attacker wrapper")
        attacker: Attacker = Attacker(self.N, self.E, self.ct, self.host, port, True)
        ic("created attacker")
        return attacker.attack()

    def attack(self):
        with Pool(len(self.ports)) as pool:
            results = pool.map(self.attacker_warper, self.ports)

        ic("got results")

        range_list = []
        s_list = []

        for result in results:
            range_list.append(result[0])
            s_list.append(result[1])

        return self.conclusion(range_list, s_list)

    def conclusion(self, ranges: list[range], S: list[int]) -> int:
        v0 = S + [0]
        vf = [r.start for r in ranges] + [
            (self.N * (self.attacker_count - 1)) // self.attacker_count
        ]
        middle = [
            ([0] * self.attacker_count).copy() for _ in range(self.attacker_count)
        ]
        for i, vec in enumerate(middle):
            vec[i] = self.N

        m = matrix(ZZ, [v0] + middle + [vf])
        ic(m)
        trans, _ = ic(m.LLL())


if __name__ == "__main__":
    HOST = "localhost"
    PORTS = [8001, 8002, 8003, 8004, 8005]
    n, e = get_public()
    ic("got public")
    parallel = ParllelAttacker(n, e, get_cipher(), HOST, PORTS)
    ic("created parallel attacker")
    parallel.attack()
    # m = matrix(ZZ, [[7, 2], [5, 3]])
    # res, t = ic(m.LLL(transformation = True))
    # ic(t * m)
