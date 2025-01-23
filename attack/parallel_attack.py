from attack.attack import Attacker
from multiprocessing import Process



class ParllelAttacker:
    
    
    def __init__(self, N: int, E: int, ct: int, host: str, ports: list[int]) -> None:        
        self.N = N
        self.E = E
        self.ct = ct
        self.host = host
        self.ports = ports
    
    def attack(self):
        for port in self.ports:
            attacker = Attacker(self.N, self.E, self.ct, self.host, port, True)
            attack_process = Process(target=attacker.attack, )
    