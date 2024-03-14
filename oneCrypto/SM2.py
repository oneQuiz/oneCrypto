from math import ceil, log
from typing import Tuple
# 模块内引用不能使用模块相对路径
from oneCrypto.SM3 import sm3
from oneCrypto.ECC import *

# 安全参数（可以理解为椭圆曲线上点坐标的比特长度）
L = 256 // 8
H = 1
K_LEN = 128 // 8


# z字节串，klen字节长度
def kdf(z: bytes, klen: int) -> bytes:
    hash_len = 256 // 8
    ha = [sm3(z + (i + 1).to_bytes(4, 'big')) for i in range(ceil(klen / hash_len))]
    return (b''.join(ha))[:klen]


def point_to_bytes(p: Tuple[int, int]):
    return b'\x04' + p[0].to_bytes(L, 'big') + p[1].to_bytes(L, 'big')


def bytes_to_point(b: bytes):
    return int.from_bytes(b[1:1 + L], 'big'), int.from_bytes(b[1 + L:], 'big')


def xor(a: bytes, b: bytes):
    assert len(a) == len(b)
    return b''.join([(a[i] ^ b[i]).to_bytes(1, 'big') for i in range(len(a))])


class SM2:
    def __init__(
            self, ecc: ECC, g: Tuple[int, int], ord_g: int = None,
            p_pub: Tuple[int, int] = None, d_pri: int = None,
            id_A: bytes = None, id_B: bytes = None
    ):
        self.ecc = ecc
        try:
            assert 32 * 8 >= d_pri.bit_length() >= 32 * 7
            assert 32 * 8 >= p_pub[0].bit_length() >= 32 * 7
            assert 32 * 8 >= p_pub[1].bit_length() >= 32 * 7

        except AssertionError:
            exit('''SM2\'s private key length is 32 bytes,
                    SM2\'s public  key length is 64 bytes,''')
        self.p_pub, self.d_pri = p_pub, d_pri
        self.g = g
        self.ord_g = ord_g
        self.id_A = id_A
        self.id_B = id_B

    # k代表加密所需的随机数
    def encrypt(self, m: bytes, k: int):
        c1 = point_to_bytes(self.ecc.power(self.g, k))
        # kg =
        x, y = self.ecc.power(self.p_pub, k)
        x_bytes = x.to_bytes(L, 'big')
        y_bytes = y.to_bytes(L, 'big')
        t = kdf(x_bytes + y_bytes, len(m))
        c2 = xor(m, t)
        c3 = sm3(x_bytes + m + y_bytes)
        return c1 + c2 + c3

    def decrypt(self, c: bytes):
        point_len = 2 * L + 1
        c1 = bytes_to_point(c[:point_len])
        x, y = self.ecc.power(c1, self.d_pri)
        x_bytes = x.to_bytes(L, 'big')
        y_bytes = y.to_bytes(L, 'big')
        hash_len = 256 // 8
        len_m = len(c) - point_len - hash_len
        t = kdf(x_bytes + y_bytes, len_m)
        c2 = c[point_len:point_len + len_m]
        m = xor(c2, t)
        c3 = c[point_len + len_m:]
        h = sm3(x_bytes + m + y_bytes)
        assert h == c3
        return m

    def Z_Gen(self, ID: bytes, p_pub: tuple):
        entl = (8 * len(ID)).to_bytes(2, 'big')

        a = self.ecc.a.to_bytes(L, 'big')
        b = self.ecc.b.to_bytes(L, 'big')
        x_g = self.g[0].to_bytes(L, 'big')
        y_g = self.g[1].to_bytes(L, 'big')
        x_A = p_pub[0].to_bytes(L, 'big')
        y_A = p_pub[1].to_bytes(L, 'big')
        Z = sm3(
            entl + ID + a + b + x_g + y_g + x_A + y_A
        )
        return Z

    def sign(self, m: bytes, k: int):
        ZA = self.Z_Gen(self.id_A, self.p_pub)
        # print('ZA',ZA)
        _m = ZA + m
        e = int.from_bytes(sm3(_m), 'big')
        x1, y1 = self.ecc.power(self.g, k)
        r = (e + x1) % self.ord_g
        s = (invmod(1 + self.d_pri, self.ord_g) * (k - r * self.d_pri)) % self.ord_g
        return r, s

    def verify(self, m, r, s):
        ZA = self.Z_Gen(self.id_A, self.p_pub)
        _m = ZA + m
        e = int.from_bytes(sm3(_m), 'big')
        t = (r + s) % self.ord_g
        x1, y1 = self.ecc.add(
            self.ecc.power(self.g, s),
            self.ecc.power(self.p_pub, t)
        )
        R = (e + x1) % self.ord_g
        return R == r


def input_bytes():
    bytes_str = input().strip().replace('\n', '').replace('\r', '')
    if bytes_str[:2] == '0x':
        bytes_str = bytes_str[2:]
    return bytes.fromhex(bytes_str)
