from Crypto.Util.number import long_to_bytes
from attack.attacker import Attacker
from eval_server.ctf_params import N, E, level_6_C, level_6_name
from eval_server.eval_client import send_answer

attacker = Attacker(N, E, level_6_C, "localhost", 8001)

r, _ = attacker.attack()
message = list(r)[0]

print(f"{r=}")
print(f"{message=}")
print(f"The message in bytes: {long_to_bytes(message)}")

print(send_answer("demo", level_6_name, message))
