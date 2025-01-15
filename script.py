from Crypto.PublicKey import RSA
from icecream import ic

with open("private_key.rsa", "rb") as key_file:
    priv_key = RSA.import_key(key_file.read())

ic(priv_key.p)
ic(priv_key.q)
ic(priv_key.n)
ic(priv_key.e)
ic(priv_key.d)