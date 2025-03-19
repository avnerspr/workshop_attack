from rsa import check_padding
from attack.bleichenbacher import search_mulitiple_intervals, search_single_interval, ceil_div
from attack.disjoint_segments import DisjointSegments




def search_single_interval(N:int,E:int,C:int, interval: range, s_list: list[int], B:int):
    a, b = interval.start, interval.stop - 1
    for r_i in range(2 * ceil_div(b * s_list[-1] - 2 * B, N), N):
        s_i = ceil_div(2 * B + r_i * N, b)
        if s_i * a < (3 * B + r_i * N):
            if check_padding(C*pow(s_i,E) % N):
                s_list.append(s_i)
                return r_i, s_i

    raise ValueError("the range of r search need to be bigger")

def outer_test_blinding(N:int,E:int,C:int):

    def test_blinding(s:str):
        try:
            s = int(s)
        except:
            return False, 'Attempt failed. Incorrect value type'
        if check_padding(C*pow(s,E) % N):
            return True, 'You successfully solved level 1. The flag for the next level is "secret_flag_3kf03jf2hmfc3IFM"'
        else:
            return False, 'Attempt failed. Incorrect blinding value'
    
    return test_blinding


def outer_test_level_2a(N:int,E:int,C:int,M:DisjointSegments, prev_s:int):
    # |M| > 1

    def test_level_2a(s:str):
        s = int(s)
        if s == search_mulitiple_intervals(C,[prev_s]):
            return True, 'You successfully solved level 2. The flag for the next level is "secret_flag_3ng9fl4ofpej46vj"'
        else:
            return False, 'Attempt failed. Incorrect value of s'

    
    return test_level_2a


def outer_test_level_2b(N:int,E:int,C:int,M:DisjointSegments,prev_s:int, B):
    # |M| == 1

    def test_level_2b(r_s:str):
        try:
            r,s = r_s.split(",")
            r, s = int(r), int(s)
        except:
            return False, 'Attempt failed. Incorrect value type'
        

        if (r, s) == search_single_interval(N,E,C,list(M)[0], [prev_s],B):
            return True, 'You successfully solved level 2. The flag for the next level is "secret_flag_5kfk19fqej61jsm3"'
        
        else:
            return False, 'Attempt failed. Incorrect value of r,s'
        


def outer_test_level_():
    pass





