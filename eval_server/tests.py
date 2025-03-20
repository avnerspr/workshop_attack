from attack.bleichenbacher import (
    search_mulitiple_intervals,
    search_single_interval,
    ceil_div,
    search_start,
    blinding,
)
from utils.rsa import check_padding
from attack.disjoint_segments import DisjointSegments
from Crypto.PublicKey import RSA
from random import randint
from typing import Any, Tuple
from Crypto.Util.number import long_to_bytes, bytes_to_long



BITS_LENGTH = 1024
E = 65537

MESSAGES = [
 77319936973372202217725276511797052350780493672174214652361474566481436230955858621081107670328511060511343668536635801544575018540889821003795139431832435663810014544708224110454983085985398547132552583805570626169402854830358970613823095819997383235855435856420284152872280769461172005611654586146640405676,
 71503456340598790086938996844327141295328350973669060615337969981676381503369982705706557333159744669103112175676052429009584888302211187971393254752011356732647480652751381600638693900980621474149649183116366745183817294884026289394093816029198858360499488411868823032975620989483996560312495620396652504098,
 58019217544429473235420433748759290094343518930348825471886608004224315553041617633570714283185434572557079820380095748901236811547183517994542481358893834428238926353356721830617860977842737063175186053711790669945206393027577014155102564012876614988717689643025620165328665196127455069166084616745060988337,
 30052992333412718285889483248871581681665442866625079365289826633852915978404616204020589984064970190349240274744401983284550959494538938641413585956205026734283303476941564917316718208191684486306434491898402902045686604522272546209195374028699985934056679139570777010641047212784866249442549952396144182619,
 48305842538243975485467575547965300177790755879716534916152217685174314012771335082562744527979809745230110779825546678989395994696110838958027077951305783213997847480332393202658036301263083320941866327445875514146449677532351874276345858042756702909341633768158843770074798394344561172189969739095830159235,
 57869433958850346942604501096326555572328695362443782976703796615080588246942514291472944988969932880585570939017514684976153289648651945929146104267562385758877452176617120392970270877540294809394307429724499430236578710811556316073215629297190515615067376052251504983479101029910327193090149210966055616386,
]


N_VALUES = [
    127558117869302158681695979007122524964499481125512781090248593527467828378726637347360866086739533457108980417299461964127414264932292332883107817595550886782155618393991400033917932206964775718582502902659454312839623598006440930221537890749345431990528942687517797705879412732353281430388519290605140893729,
    133095037975438514502110601108540144345222824263697809024750114351129124449000790836417728060721277801737332844785617997719208542149807349760150068843790302607575721480195453540393508936794670429641449817199299178061477114123391538128583683679247943172226535133597770160454827609680009469305286502909124616279,
    99645530795816963805982283891340851981078138780743228759049794950924754624583291810949554650429362802503514393570522558722466194168398014726212849193326088703268431396339984662288344482442135964572123059926710093178273496419797907443707520136107541725955325697563728072708187522864373363040416934417086840487,
    152002560715910850229387520275268506841587700763895290655150547950932713179711419731255319018279063940057612246146711787810612166613871365688479175210627487594968861894227099568026496470078519737372371333346739823157029253111998115806693886260852165771810841970795963041682372543867885149091089823617030135719,
    120740105052480003079535382788327113290065861489734876606095370765277026418319224621417364489165125542563206812481465937293272494096548570894996246895358086532277007249310386668745874967475700150220085601362391279567615192716721380904470682748453258272629110672718271879143030081112941193548133194713660231447,
    135890389024794533347599981856240123202682375565796757417665128720852595398532591234835885975598460592551561978667245509205948023169255728497057795481447022873011043380052828252219001578920373736739667604414186370258342421725641632584348453369074908926071814452535977698504845417990384631928104254984727493749,
]

D_VALUES = [
    20311163755208549016934531469686239975388472699166709295013338995619123900181604651393629828160739756041026674164647990091881403813127494999796628324738255381519589854886740545999251077637297319675583009887707135523940321840728658878807389055723491255252043840801355987416636301281631344020520798948719748777,
    4004812775799391955661109074050401523548215656011292543094850626370243273470399309236244560107151072295436476645516863626688424021841403996628102228664028430293717056879562439874840832817571444580132946552573168179980762937926651315675140248503749315543805051513038076014975048070409693635182583984630270177,
    32368794804646952751355064189126072261854715603449083678706853910161238707947475462155806169842847623517971801039456410159796493700520703350875770121865796071754587186702302319023608845861557645024026327017839943898271054604825750274781025253037797105318113602328547485395586303169988075365268663584382400865,
    129126712356129291531123619987966520744440446072724879396982041111306748877083355479826819369149150645897188167315286515411134420151021416885713801136701714621071483231176531020191583836769125593381771979629598153716578678984556421875200348914748401329404770386808917586425607237345678078708800356113980873,
    14548798535169973973771929106907841580353847569837440233125335961874859661343468831886307389275325333927730048646812281715747942168247616832595104471255056467175856820889784747572524560342753134545053598202093461010486812921491184602448922956907504914737066602955134354659455983646774808448778059316233173153,
    12903335381559979569130638983953831983311601433479610317990297023511385952440122606380879784337843054571438579630533420873531204482693415909138206834018106992767788402513117909055056930852964768791378518993363365524108232616034367732175442328443719559169040087289226060566608360875026127797411850272759767029,
]


# def check_padding(self, ciphertext, sentinel, expected_pt_len=0):

#     k = self._key.size_in_bytes()

#     if len(ciphertext) != k:
#         raise ValueError("Ciphertext with incorrect length (not %d bytes)" % k)

#     ct_int = bytes_to_long(ciphertext)

#     em = self._key._decrypt_to_bytes(ct_int)
#     return em[0:2] == b"\x00\x02"



# BITS_LENGTH = 1024
# E = 65537
# CONST_MESSAGE_1 = randint(0, 1 << BITS_LENGTH - 1)
# CONST_MESSAGE_2 = randint(0, 1 << BITS_LENGTH - 1)
# CONST_MESSAGE_3 = randint(0, 1 << BITS_LENGTH - 1)
# CONST_MESSAGE_4 = randint(0, 1 << BITS_LENGTH - 1)
# CONST_MESSAGE_5 = randint(0, 1 << BITS_LENGTH - 1)
# CONST_MESSAGE_6 = randint(0, 1 << BITS_LENGTH - 1)

# PRIVATE_KEY_1 = RSA.generate(BITS_LENGTH)
# PRIVATE_KEY_2 = RSA.generate(BITS_LENGTH)
# PRIVATE_KEY_3 = RSA.generate(BITS_LENGTH)
# PRIVATE_KEY_4 = RSA.generate(BITS_LENGTH)
# PRIVATE_KEY_5 = RSA.generate(BITS_LENGTH)
# PRIVATE_KEY_6 = RSA.generate(BITS_LENGTH)

# print(CONST_MESSAGE_1)
# print("\n\n")
# print(CONST_MESSAGE_2)
# print("\n\n")
# print(CONST_MESSAGE_3)
# print("\n\n")
# print(CONST_MESSAGE_4)
# print("\n\n")
# print(CONST_MESSAGE_5)
# print("\n\n")
# print(CONST_MESSAGE_6)
# print("\n\n")



def string_to_DisjointSegments(M: str):
    return DisjointSegments.deserialize(M)


def get_params_mNEC(level_num):
    global E
    index = level_num - 1
    m = MESSAGES[index]
    N = N_VALUES[index]
    d = D_VALUES[index]
    C = pow(m,E, N)
    return m, N, E, C

def get_NEC(key: RSA.RsaKey, m):
    return key.n, key.e, pow(m, key.d, key.n)


def blinding(N: int, E: int, C: int) -> Tuple[int, int]:
    for s0 in range(1, N):
        C0 = C * pow(s0, E, N) % N
        if check_padding(C0):
            return C0, s0


def search_single_interval(
    N: int, E: int, C: int, interval: range, s_list: list[int], B: int
):

    a, b = interval.start, interval.stop - 1
    for r_i in range(2 * ceil_div(b * s_list[-1] - 2 * B, N), N):
        s_i = ceil_div(2 * B + r_i * N, b)
        if s_i * a < (3 * B + r_i * N):
            if check_padding(C * pow(s_i, E) % N):

                s_list.append(s_i)
                return r_i, s_i

    raise ValueError("the range of r search need to be bigger")


def update_intervals(
    N: int, prev_M: DisjointSegments, prev_s: int, B: int
) -> DisjointSegments:
    M_res = DisjointSegments()
    for interval in prev_M:
        a, b = interval.start, interval.stop - 1
        r_range = range(
            ((a * prev_s - 3 * B + 1) // N), ((b * prev_s - 2 * B) // N) + 1
        )
        for r in r_range:
            pos_sol_range = range(
                max(a, ceil_div(2 * B + r * N, prev_s)),
                (min(b, (((3 * B - 1 + r * N) // prev_s))) + 1),
            )

            M_res.add(pos_sol_range)

    assert len(M_res) >= 1
    return M_res


def outer_test_blinding(N: int, E: int, C: int):  # Challenge #1

    def test_blinding(s: str):
        try:
            s = int(s)
        except:
            return False, "Attempt failed. Incorrect value format"
        if check_padding(C * pow(s, E) % N):
            return (
                True,
                'You successfully solved level 1. The flag for the next level is "secret_flag_3Kf03JF2hmfc3IxM"',
            )
        else:
            return False, "Attempt failed. Incorrect blinding value"

    return test_blinding


def generate_params_blinding(key: RSA.RsaKey) -> dict[str, Any]:
    m = MESSAGES[0]
    N, E, C = get_NEC(key, m)
    return {"N": str(N), "E": str(E), "C": str(C)}


def outer_test_level_2a(N: int, E: int, C0: int):  # Challenge #2

    def test_level_2a(s1):
        try:
            s1 = int(s1)
        except:
            return False, "Attempt failed. Incorrect value format"
        if s1 == search_start(C0, list()):
            return (
                True,
                'You successfully solved level 2. The flag for the next level is "secret_flag_G5kqD94kd0soFjZ1"',
            )

        else:
            return False, "Attempt failed. Incorrect value of s1"

    return test_level_2a


def generate_params_level_2a(key: RSA.RsaKey) -> dict[str, str]:
    m = MESSAGES[1]
    N, E, C = get_NEC(key, m)
    C0, s0 = blinding(N, E, C)
    return {"N": str(N), "E": str(E), "C0": str(C0)}


def outer_test_level_2b(
    N: int, E: int, C: int, M: DisjointSegments, prev_s: int
):  # Challenge #3
    # |M| > 1

    def test_level_2b(s: str):
        try:
            s = int(s)
        except:
            return False, "Attempt failed. Incorrect value format"
        if s == search_mulitiple_intervals(C, [prev_s]):
            return (
                True,
                'You successfully solved level 3. The flag for the next level is "secret_flag_3nG9fL4ofpEj46vj"',
            )
        else:
            return False, "Attempt failed. Incorrect value of s"

    return test_level_2b


def generate_params_level_2b(key: RSA.RsaKey) -> dict[str, str]:
    m = MESSAGES[2]
    N, E, C = get_NEC(key, m)
    K = len(long_to_bytes(N))  # TODO better than this
    B = pow(
        2, 8 * (K - 2)
    )  # the value of the lsb in the second most significant byte of N

    C0, s0 = blinding(N, E, C)
    # s_list = [s0]
    # M: DisjointSegments = DisjointSegments([range(2 * B, 3 * B)])
    # MAX_ITER = 1_000_000
    # for iteration in range(1, MAX_ITER + 1):
    #     # steps 2-4
    #     res, M = algo_iteration(C0, M, s_list, iteration)
    #     if res:
    #         assert isinstance(M, int)
    #         result = M
    #         ans_num = result * pow(s0, -1, N) % N
    #         ans = long_to_bytes(ans_num, KEY_SIZE // 8)
    #         print(f"{ans = }")
    #         break

    # update_intervals(N, prev_M, prev_s, B)


def outer_test_level_2c(
    N: int, E: int, C: int, M: DisjointSegments, prev_s: int, B
):  # Challenge #4
    # |M| == 1

    def test_level_2c(s: str):
        try:
            # r,s = r_s.split(",")
            # r, s = int(r), int(s)
            s = int(s)
        except:
            return False, "Attempt failed. Incorrect value format"

        # if (r, s) == search_single_interval(N,E,C,list(M)[0], [prev_s],B):
        if s == search_single_interval(N, E, C, list(M)[0], [prev_s], B)[1]:
            return (
                True,
                'You successfully solved level 4. The flag for the next level is "secret_flag_5Kfk19fqeJ61jsm3"',
            )

        else:
            return False, "Attempt failed. Incorrect value of r,s"

    return test_level_2c


def outer_test_compute_M(
    N: int, E: int, C: int, prev_M: DisjointSegments, prev_s: int, B: int
):  # Challenge #5

    def test_compute_M(M: str):
        try:
            M = string_to_DisjointSegments(M)
        except:
            return False, "Attempt failed. Incorrect value format"

        if M == update_intervals(N, prev_M, prev_s, B):
            return (
                True,
                'You successfully solved level 5. The flag for the next level is "secret_flag_o1q9cMf43kVl2a6x"',
            )
        else:
            return False, "Attempt failed. Incorrect value of M"

    return test_compute_M


def outer_test_level_final(message: int):  # Challenge #6

    def test_level_final(m: str):
        try:
            m = int(m)
        except:
            return False, "Attempt failed. Incorrect value format"

        if m == message:
            return (
                True,
                'You successfully solved level 6. The flag for the next level is "secret_flag_p0voqE4iUv0Q8t35"',
            )
        else:
            return False, "Attempt failed. Incorrect value of M"

    return test_final_level


def get_params_final_level():
    m, N, E, C = get_params_mNEC(level_num=6)
    pass #TODO implement


TESTERS = [
    outer_test_blinding,
    outer_test_level_2a,
    outer_test_level_2b,
    outer_test_level_2c,
    outer_test_compute_M,
    outer_test_final_level,
]


GET_PARAMS = [
    get_params_blinding, 
    get_params_level_2a,
    get_params_level_2b,
    get_params_level_2c,
    get_params_compute_M,
    get_params_final_level,
]

NAMES = [
    "blinding", 
    "level_2a",
    "level_2b",
    "level_2c",
    "compute_M",
    "final_level",
]
