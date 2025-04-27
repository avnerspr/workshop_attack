from attack.attacker import Attacker
from eval_server.ctf_params import (
    N,
    E,
    level_3_C,
    level_3_M,
    level_3_prev_s,
    level_3_name,
)
from eval_server.eval_client import send_answer

attacker = Attacker(N, E, level_3_C, "localhost", 8001, random_blinding=True)
attacker.s_list = [level_3_prev_s]
attacker.M = level_3_M

si = attacker.search_mulitiple_intervals()

print(f"{si=}")

print(send_answer("demo", level_3_name, si))
