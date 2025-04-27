from attack.attacker import Attacker
from eval_server.ctf_params import N, E, level_2_C0, level_2_name
from eval_server.eval_client import send_answer

attacker = Attacker(N, E, level_2_C0, "localhost", 8001, random_blinding=True)
s1 = attacker.search_start()

print(f"{s1=}")

print(send_answer("demo", level_2_name, s1))
