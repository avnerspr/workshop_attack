import random
from Crypto.Util.number import bytes_to_long, getPrime, isPrime
from Crypto.PublicKey.RSA import RsaKey
from icecream import ic


def check_padding(self, ciphertext, sentinel, expected_pt_len=0):
    k = self._key.size_in_bytes()

    if len(ciphertext) != k:
        raise ValueError("Ciphertext with incorrect length (not %d bytes)" % k)

    ct_int = bytes_to_long(ciphertext)

    em = self._key._decrypt_to_bytes(ct_int)
    return em[0:2] == b"\x00\x02"


def check_padding_private_key(ciphertext: bytes, private_key: RsaKey) -> bool:
    """
    Decrypts `ciphertext` using the given `private_key` and returns
    whether it's PKCS #1 v1.5 compliant (not fully, but just checking the first two bytes).
    """
    deciphered = private_key._decrypt_to_bytes(bytes_to_long(ciphertext))
    return deciphered[0:2] == b"\x00\x02"
