from rsa import check_padding
from attack.bleichenbacher import search_mulitiple_intervals, search_single_interval, ceil_div, search_start
from attack.disjoint_segments import DisjointSegments



def string_to_DisjointSegments(M:str):
    return DisjointSegments.deserialize(M)

def search_single_interval(N:int,E:int,C:int, interval: range, s_list: list[int], B:int):
    a, b = interval.start, interval.stop - 1
    for r_i in range(2 * ceil_div(b * s_list[-1] - 2 * B, N), N):
        s_i = ceil_div(2 * B + r_i * N, b)
        if s_i * a < (3 * B + r_i * N):
            if check_padding(C*pow(s_i,E) % N):
                s_list.append(s_i)
                return r_i, s_i

    raise ValueError("the range of r search need to be bigger")


def update_intervals(N:int, prev_M: DisjointSegments, prev_s: int, B:int) -> DisjointSegments:
    M_res = DisjointSegments()
    for interval in prev_M:
        a, b = interval.start, interval.stop - 1
        r_range = range(((a * prev_s - 3 * B + 1) // N), ((b * prev_s - 2 * B) // N) + 1)
        for r in r_range:
            pos_sol_range = range(
                max(a, ceil_div(2 * B + r * N, prev_s)),
                (min(b, (((3 * B - 1 + r * N) // prev_s))) + 1),
            )

            M_res.add(pos_sol_range)

    assert len(M_res) >= 1
    return M_res

def outer_test_blinding(N:int,E:int,C:int): # Challenge #1

    def test_blinding(s:str):
        try:
            s = int(s)
        except:
            return False, 'Attempt failed. Incorrect value format'
        if check_padding(C*pow(s,E) % N):
            return True, 'You successfully solved level 1. The flag for the next level is "secret_flag_3Kf03JF2hmfc3IxM"'
        else:
            return False, 'Attempt failed. Incorrect blinding value'
    
    return test_blinding


def outer_test_level_2a(N:int,E:int,C0:int): # Challenge #2

    def test_level_2a(s1):
        try:
            s1 = int(s1)
        except:
            return False, 'Attempt failed. Incorrect value format'
        if s1 == search_start(C0, list()):
            return True, 'You successfully solved level 2. The flag for the next level is "secret_flag_G5kqD94kd0soFjZ1"'
 
        else:
            return False, 'Attempt failed. Incorrect value of s1'
        
    return test_level_2a



def outer_test_level_2b(N:int,E:int,C:int,M:DisjointSegments, prev_s:int): # Challenge #3
    # |M| > 1

    def test_level_2b(s:str):
        try:
            s = int(s)
        except:
            return False, 'Attempt failed. Incorrect value format'
        if s == search_mulitiple_intervals(C,[prev_s]):
            return True, 'You successfully solved level 3. The flag for the next level is "secret_flag_3nG9fL4ofpEj46vj"'
        else:
            return False, 'Attempt failed. Incorrect value of s'

    
    return test_level_2b


def outer_test_level_2c(N:int,E:int,C:int,M:DisjointSegments,prev_s:int, B): # Challenge #4
    # |M| == 1

    def test_level_2c(s:str):
        try:
            #r,s = r_s.split(",")
            #r, s = int(r), int(s)
            s = int(s)
        except:
            return False, 'Attempt failed. Incorrect value format'
        

        #if (r, s) == search_single_interval(N,E,C,list(M)[0], [prev_s],B):
        if s == search_single_interval(N,E,C,list(M)[0], [prev_s],B)[1]: 
            return True, 'You successfully solved level 4. The flag for the next level is "secret_flag_5Kfk19fqeJ61jsm3"'
        
        else:
            return False, 'Attempt failed. Incorrect value of r,s'
    
    return test_level_2c
        

def outer_test_compute_M(N:int,E:int,C:int,prev_M:DisjointSegments,prev_s:int,B:int): # Challenge #5

    def test_compute_M(M:str):
        try:
            M = string_to_DisjointSegments(M)
        except:
            return False, 'Attempt failed. Incorrect value format'
        
        if M == update_intervals(N, prev_M, prev_s, B):
            return True, 'You successfully solved level 5. The flag for the next level is "secret_flag_o1q9cMf43kVl2a6x"'
        else: 
            return False, 'Attempt failed. Incorrect value of M'
    
    return test_compute_M


def outer_test_level_final(m:int): # Challenge #6
    
    def test_level_final(m_candidate:str):
        try:
            m = int(m)
        except:
            return False, 'Attempt failed. Incorrect value format'


    return test_level_final 





