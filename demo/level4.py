from attack.attacker import Attacker
from eval_server.ctf_params import (
    N,
    E,
    level_4_C,
    level_4_M,
    level_4_prev_s,
    level_4_name,
)
from eval_server.eval_client import send_answer

attacker = Attacker(N, E, level_4_C, "localhost", 8001, random_blinding=True)
attacker.s_list = [level_4_prev_s]
attacker.M = level_4_M

si = attacker.search_single_interval(level_4_M.tolist()[0])

print(f"{si=}")

print(send_answer("demo", level_4_name, si))
