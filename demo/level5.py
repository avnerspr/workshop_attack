from attack.attacker import Attacker
from eval_server.ctf_params import (
    N,
    E,
    level_5_C,
    level_5_prev_M,
    level_5_prev_s,
    level_5_name,
)
from eval_server.eval_client import send_answer

attacker = Attacker(N, E, level_5_C, "localhost", 8001, random_blinding=True)
attacker.M = level_5_prev_M

next_M = attacker.update_intervals(level_5_prev_s)

print(f"{next_M=}")

print(send_answer("demo", level_5_name, next_M))
