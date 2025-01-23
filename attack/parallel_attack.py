from attack.attack import Attacker
from multiprocessing import Process, Pool



class ParllelAttacker:
    
    
    def __init__(self, N: int, E: int, ct: int, host: str, ports: list[int]) -> None:        
        self.N = N
        self.E = E
        self.ct = ct
        self.host = host
        self.ports = ports
    

    def attacker_warper(self, port):
        attacker = Attacker(self.N, self.E, self.ct, self.host, port, True)
        return attacker.attack()
    

    def attack(self):
        with Pool(len(self.ports)) as pool:
            results = pool.map(self.attacker_warper, self.ports)

        range_list = []
        s_list = []

        for result in results:
            range_list.append(result[0])
            s_list.append(result[1])

    