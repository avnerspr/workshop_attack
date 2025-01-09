import random
from Crypto.Util.number import bytes_to_long, getPrime, isPrime


def check_padding(self, ciphertext, sentinel, expected_pt_len=0):
    r"""Decrypt a PKCS#1 v1.5 ciphertext.

    This is the function ``RSAES-PKCS1-V1_5-DECRYPT`` specified in
    `section 7.2.2 of RFC8017
    <https://tools.ietf.org/html/rfc8017#page-29>`_.

    Args:
        ciphertext (bytes/bytearray/memoryview):
        The ciphertext that contains the message to recover.
        sentinel (any type):
        The object to return whenever an error is detected.
        expected_pt_len (integer):
        The length the plaintext is known to have, or 0 if unknown.

    Returns (byte string):
        It is either the original message or the ``sentinel`` (in case of an error).

    .. warning::
        PKCS#1 v1.5 decryption is intrinsically vulnerable to timing
        attacks (see `Bleichenbacher's`__ attack).
        **Use PKCS#1 OAEP instead**.

        This implementation attempts to mitigate the risk
        with some constant-time constructs.
        However, they are not sufficient by themselves: the type of protocol you
        implement and the way you handle errors make a big difference.

        Specifically, you should make it very hard for the (malicious)
        party that submitted the ciphertext to quickly understand if decryption
        succeeded or not.

        To this end, it is recommended that your protocol only encrypts
        plaintexts of fixed length (``expected_pt_len``),
        that ``sentinel`` is a random byte string of the same length,
        and that processing continues for as long
        as possible even if ``sentinel`` is returned (i.e. in case of
        incorrect decryption).

        .. __: https://dx.doi.org/10.1007/BFb0055716
    """

    # See 7.2.2 in RFC8017
    k = self._key.size_in_bytes()

    # Step 1
    if len(ciphertext) != k:
        raise ValueError("Ciphertext with incorrect length (not %d bytes)" % k)

    # Step 2a (O2SIP)
    ct_int = bytes_to_long(ciphertext)

    # Step 2b (RSADP) and Step 2c (I2OSP)
    em = self._key._decrypt_to_bytes(ct_int)

    # Step 3 (not constant time when the sentinel is not a byte string)
    return em[0:2] == b"\x00\x02"
