from attack import Attacker
from multiprocessing import Process
from sage.all import matrix, ZZ, IntegralLattice
from icecream import ic

class ParllelAttacker:
    
    
    def __init__(self, N: int, E: int, ct: int, host: str, ports: list[int]) -> None:        
        self.N = N
        self.E = E
        self.ct = ct
        self.attacker_count = len(ports)
        self.host = host
        self.ports = ports
    
    def attack(self):
        for port in self.ports:
            attacker = Attacker(self.N, self.E, self.ct, self.host, port, True)
            attack_process = Process(target=attacker.attack)
    
    
    
    def conclusion(self, ranges: list[range], S: list[int]) -> int:
        v0 = S + [0]
        vf = [r.start for r in ranges] + [(self.N * (self.attacker_count - 1)) // self.attacker_count]
        middle = [([0] * self.attacker_count).copy() for _ in range(self.attacker_count)]
        for i, vec in enumerate(middle):
            vec[i] = self.N
        
        m = matrix(ZZ, [v0] + middle + [vf])
        trans, _ = ic(m.LLL())
        
        


# if __name__ == "__main__":
#     m = matrix(ZZ, [[7, 2], [5, 3]])
#     res, t = ic(m.LLL(transformation = True))
#     ic(t * m)