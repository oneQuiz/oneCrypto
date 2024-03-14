import random

O = (0, 0)


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


class ECC:
    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.module = p

    def is_opposite(self, p1, p2):
        return p1[0] == p2[0] and p1[1] == -p2[1] % self.module

    def add(self, p1, p2):
        if p1 == O:
            return p2
        if p2 == O:
            return p1
        if self.is_opposite(p1, p2):
            return O
        x1, y1 = p1
        x2, y2 = p2
        l = 0
        if x1 != x2:
            l = (y2 - y1) * invmod(x2 - x1, self.module)
        else:
            l = (3 * x1 ** 2 + self.a) * invmod(2 * y1, self.module)
        x = (l * l - x1 - x2) % self.module
        y = (l * (x1 - x) - y1) % self.module
        return x, y

    def sub(self, p1, p2):
        p2 = p2[0], -p2[1]
        return self.add(p1, p2)

    def power(self, p, n):
        if n == 0 or p == O:
            return O
        res = O
        # 快速模幂！
        while n:
            if n & 1:
                res = self.add(res, p)
            p = self.add(p, p)
            n >>= 1
        return res

    def inv_power(self, p, n):
        n = invmod(n, self.module)
        return self.power(p, n)

    def encrypt(self, p_m:tuple, p_pub:tuple, g:tuple, k:int):
        return self.power(g, k), self.add(p_m, self.power(p_pub, k))

    # c1=kg,c2=pm+kpa
    def decrypt(self, c1:tuple, c2:tuple, n_pri:int):
        return self.sub(c2, self.power(c1, n_pri))
    def DH(self,p_g,r,p_pub):
        return self.power(p_pub,r)

def print_point(p):
    print(f"{p[0]} {p[1]}")


def input_point():
    x, y = map(int, input().split())
    return x, y


if __name__ == '__main__':
    p = int(input())
    a = int(input())
    b = int(input())
    ecc = ECC(a, b, p)
    p_g = input_point()
    r =int(input())
    p_pub = input_point()
    k = ecc.DH(p_g,r,p_pub)
    print_point(k)