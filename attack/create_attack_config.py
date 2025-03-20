from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Util.number import bytes_to_long
import json


# ! only for testing
def get_public() -> tuple[int, int]:
    with open("public_key.rsa", "rb") as key_file:
        pub_key = RSA.import_key(key_file.read())
    return pub_key.n, pub_key.e


def get_cipher(to_cypher: str) -> int:
    msg = to_cypher.encode("utf-8")
    with open("public_key.rsa", "rb") as key_file:
        pub_key = RSA.import_key(key_file.read())
    cipher_rsa = PKCS1_v1_5.new(pub_key)

    return bytes_to_long(cipher_rsa.encrypt(msg))


if __name__ == "__main__":
    N, E = get_public()
    C = get_cipher("hello world")
    with open("attack/servers_addr.json", "w") as file:
        json.dump(
            {
                "hosts": ["localhost"] * 5,
                "ports": [8001, 8002, 8003, 8004, 8005],
                "N": N,
                "E": E,
                "C": C,
            },
            file,
        )
