from attack.attacker import Attacker
from attack.create_attack_config import get_cipher, get_public
from eval_server.eval_client import send_answer
from Crypto.Util.number import long_to_bytes

if __name__ == "__main__":
    N, E = get_public()
    message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Praesent pharetra orci ac nisi auctor."
    C = get_cipher(message)
    host = "localhost"
    port = 8888
    attacker = Attacker(N, E, C, host, port)
    answer = attacker.attack()

    print(answer)

    # answer = send_answer("eyal", "blinding", s0)
    # print(answer)
