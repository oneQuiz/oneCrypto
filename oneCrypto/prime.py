# 利用Miller-Rabin素性检验
from random import randint


def isPrime(p):
    if p < 2:
        return False
    if p == 2:
        return True
    if (p & 1) == 0:
        return False

    d = p - 1
    r = 0
    while (d & 1) == 0:
        r += 1
        d >>= 1
    # p-1 = (2^r)*q
    # 现在 d = q
    for i in range(100):  # 进行一百次检验
        a = randint(1, 65536) % (p - 2) + 2
        x = pow(a, d, p)

        if x == 1 or x == p - 1:
            continue
        for i in range(r):
            x = x * x % p
            if x == p - 1:
                break
        if x != p - 1:
            return False
    return True


def isStrongPrime(p):
    if not isPrime(p):
        return False
    lp, rp = p - 2, p + 2
    while not isPrime(lp):
        lp -= 2
    while not isPrime(rp):
        rp += 2
    return p > (lp + rp) // 2


def getStrongPrime(N):
    n = randint(2 ** (N - 1), 2 ** N) | 1  # 取一个Nbit的奇数
    while (not isStrongPrime(n)):
        n = n + 2
    return n


def getPrime(N):
    n = randint(2 ** (N - 1), 2 ** N) | 1  # 取一个Nbit的奇数
    while (not isPrime(n)):
        n = n + 2
    return n
