from attack.attacker import Attacker
from eval_server.ctf_params import N, E, level_1_C, level_1_name
from eval_server.eval_client import send_answer

attacker = Attacker(N, E, level_1_C, "localhost", 8001, random_blinding=True)
blinded_C, blinding_s = attacker.blinding()
print(f"{blinding_s=}")

print(send_answer("demo", level_1_name, blinding_s))
