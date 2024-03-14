# 输入任意长度的十六进制字节串（有无 0x都可），返回字节列表
def input_bytes():
    bytes_str = input().strip().replace('\n', '').replace('\r', '')
    if bytes_str[:2] == '0x':
        bytes_str = bytes_str[2:]
    res = []
    for i in range(0, len(bytes_str), 2):
        res.append(int(bytes_str[i:i + 2], 16))
    return res


# 输入任意长度的任意格式的十六进制字节串（有无 0x都可），返回字节列表
def input_any_bytes():
    res = []
    b_line = input()
    while True:
        b_ls = list(map(lambda x: int(x, 16), b_line.split()))
        for b in b_ls:
            res.append(b)
        try:
            b_line = input()
        except EOFError:
            break
    return res


def str2int(s):
    return int.from_bytes(s.encode("utf-8"), "big")
def int2str(n:int):
    nbytes = (n.bit_length() + 7) >> 3
    return (n.to_bytes(nbytes, "big")).decode('utf-8')

# 返回整数对应的指定长度的十六进制字节串，补充前导零
def HEX(n, l):
    h = hex(n)[2:]
    while len(h) < l:
        h = '0' + h
    return '0x' + h


# 32位字循环左移
def left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff


# 扩欧运算 ax+by=g，返回 x, y, g
def exgcd(a, b):
    if a == 0:
        return 0, 1, b
    if b == 0:
        return 1, 0, a

    px, ppx = 0, 1
    py, ppy = 1, 0

    while b:
        q = a // b
        a, b = b, a % b
        x = ppx - q * px
        y = ppy - q * py
        ppx, px = px, x
        ppy, py = py, y

    return ppx, ppy, a


def invmod(a, n):
    x, y, g = exgcd(a, n)

    assert g == 1
    return x % n


def fastpow(base, expo, p):
    res = 1
    while expo > 0:
        if expo % 2 == 1:
            res = (res * base) % p
        expo >>= 1
        base = (base * base) % p
    return res

def CRT(a: list, p: list):
    #
    # if not isCoprime(p):
    #     a, p = preCRT(a, p)
    P = 1
    assert isCoprime(p) == True
    for _ in p:
        P *= _
    res = 0
    e = []
    for i in range(len(a)):
        # 求得P/p[i]模p[i]的逆元列表
        e.append(invmod(P // p[i], p[i]))
        res += P // p[i] * e[i] * a[i]
    if res % P == 0:
        return P
    else:
        return res % P


def isCoprime(pls: list):
    d = gcd(pls[0], pls[1])
    for i in range(2, len(pls)):
        d = gcd(d, pls[i])
    if d == 1:
        return True
    else:
        return False


def LCM(a, b):
    return a * b // gcd(a, b)
def gcd(a, b):
    if b == 0:
        return a
    elif a == 0:
        return b
    else:
        return gcd(b, a % b)
