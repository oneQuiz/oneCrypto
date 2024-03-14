from functools import reduce
from math import ceil

SBOX = (
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
)

FK = (0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc)

CK = (
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
)
ENCRYPT = 1
DECRYPT = 0
BLOCK_BYTES = 16


def HEX(n, l):
    h = hex(n)[2:]
    while len(h) < l:
        h = '0' + h
    return '0x' + h


# range(32,0,-8)
def ANY_TO_BYTES(n, bit_len):
    return [int((n >> i) & 0xff) for i in range(bit_len - 8, -1, -8)]


def BYTES_TO_ANY(b: list, bit_len):
    res = 0
    for i in range(len(b)):
        res |= b[i] << (bit_len - (i + 1) * 8)
    return int(res)


def BYTES_TO_DWORD(bytes):
    return int((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | (bytes[3]))


def DWORD_TO_BYTES(dword):
    return [int((dword >> 24) & 0xff), int((dword >> 16) & 0xff), int((dword >> 8) & 0xff), int((dword) & 0xff)]


def SHL(x, n):
    return int(int(x << n) & 0xffffffff)


def ROTL(x, n):
    return SHL(x, n) | int((x >> (32 - n)) & 0xffffffff)


def XOR(a, b):
    return list(map(lambda x, y: x ^ y, a, b))


def F_fuc(dw0, dw1, dw2, dw3, rk):
    return dw0 ^ T_fuc(dw1 ^ dw2 ^ dw3 ^ rk)


def T_fuc(dw):
    res = BYTES_TO_DWORD([SBOX[byte] for byte in DWORD_TO_BYTES(dw)])
    return res ^ (ROTL(res, 2)) ^ (ROTL(res, 10)) ^ \
           (ROTL(res, 18)) ^ (ROTL(res, 24))


def rk_T_fuc(dw):
    res = BYTES_TO_DWORD([SBOX[byte] for byte in DWORD_TO_BYTES(dw)])
    return res ^ (ROTL(res, 13)) ^ (ROTL(res, 23))


class SM4:
    def __init__(self, mode, k: list):
        self.sk = [0] * 36
        self.mode = mode
        try:
            assert len(k) == 16
        except AssertionError:
            exit('SM4\'s key length is 128 bits!!!')
        self._rk_init(k)

    def _rk_init(self, key):
        MK = [BYTES_TO_DWORD(key[i * 4:i * 4 + 4]) for i in range(4)]
        k = [0] * 36
        k[0:4] = XOR(MK, FK)
        for i in range(32):
            k[i + 4] = k[i] ^ (rk_T_fuc(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]))
        self.sk = k[4:]
        if self.mode == DECRYPT:
            self.sk.reverse()

    def chmod(self, mode):
        if self.mode != mode:
            self.sk.reverse()
        self.mode = mode

    def one_round(self, b_input):
        init = [BYTES_TO_DWORD(b_input[i * 4:i * 4 + 4]) for i in range(4)]
        res = reduce(lambda x, rk: [x[1], x[2], x[3],
                                    F_fuc(x[0], x[1], x[2], x[3], rk)],
                     self.sk, init)
        res.reverse()
        b_output = [0] * 16
        for i in range(4):
            b_output[i * 4:i * 4 + 4] = DWORD_TO_BYTES(res[i])
        return b_output

    def _padding(self, b_input: list):
        if self.mode == ENCRYPT:
            p_num = 16 - (len(b_input) % 16)
            for i in range(p_num):
                b_input.append(p_num)

    def _inv_padding(self, b_output: list):
        if self.mode == DECRYPT:
            if self.mode == DECRYPT:
                p_num = b_output[-1]
                while p_num > 0:
                    b_output.pop()
                    p_num -= 1

    def ecb(self, b_input):
        if isinstance(b_input, bytes):
            b_input = list(b_input)
        self._padding(b_input)
        res = []
        for j in range(0, len(b_input), 16):
            tmp = self.one_round(b_input[j:j + 16])
            for b in tmp:
                res.append(b)
        self._inv_padding(res)
        return res

    def cbc(self, b_input, iv):
        if isinstance(b_input, bytes):
            b_input = list(b_input)
        self._padding(b_input)
        res = []
        buf = iv
        if self.mode == ENCRYPT:
            for j in range(0, len(b_input), 16):
                buf = self.one_round(XOR(b_input[j:j + 16], buf))
                for b in buf:
                    res.append(b)
        else:
            buf = XOR(self.one_round(b_input[0:16]), buf)
            for b in buf:
                res.append(b)
            for j in range(16, len(b_input), 16):
                buf = XOR(self.one_round(b_input[j:j + 16]), b_input[j - 16:j])
                for b in buf:
                    res.append(b)
        self._inv_padding(res)
        return res

    def ctr(self, b_input, iv):
        if isinstance(b_input, bytes):
            b_input = list(b_input)
        length = ceil(len(b_input) / 16)
        d = 16 if len(b_input) % 16 == 0 else len(b_input) % 16
        ctr_init = BYTES_TO_ANY(iv, 128)
        CEIL = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF + 1
        ctr_ls = [ANY_TO_BYTES((ctr_init + i) % CEIL, 128) for i in range(length)]
        res = []
        for i in range(length - 1):
            ci = XOR(self.one_round(ctr_ls[i]), b_input[i * 16:(i + 1) * 16])
            for b in ci:
                res.append(b)
        c_last = XOR(self.one_round(ctr_ls[-1]), b_input[-d:])
        for b in c_last:
            res.append(b)
        return res

    def ofb(self, b_input, iv, n=2):
        self.chmod(ENCRYPT) 
        if isinstance(b_input, bytes):
            b_input = list(b_input)
        length = ceil(len(b_input) / n)
        d = n if len(b_input) % n == 0 else len(b_input) % n
        buf = iv
        res = []
        for i in range(length - 1):
            o_i = self.one_round(buf)[:n]
            in_i = b_input[i * n:(i + 1) * n]
            res_i = XOR(o_i, in_i)
            for b in res_i:
                res.append(b)
            buf = buf[n:] + o_i
        o_n = self.one_round(buf)[:d]
        in_n = b_input[-d:]
        res_n = XOR(o_n, in_n)
        for b in res_n:
            res.append(b)
        return res

    def cfb(self, b_input, iv, mode, n=2):
        self.mode = ENCRYPT
        if isinstance(b_input, bytes):
            b_input = list(b_input)
        length = ceil(len(b_input) / n)
        d = n if len(b_input) % n == 0 else len(b_input) % n
        buf = iv
        res = []
        for i in range(length - 1):
            o_i = self.one_round(buf)[:n]
            in_i = b_input[i * n:(i + 1) * n]
            res_i = XOR(o_i, in_i)
            for b in res_i:
                res.append(b)
            if mode == ENCRYPT:
                buf = buf[n:] + res_i
            else:
                buf = buf[n:] + in_i
        o_n = self.one_round(buf)[:d]
        in_n = b_input[-d:]
        res_n = XOR(o_n, in_n)
        for b in res_n:
            res.append(b)
        return res

    def file_process(self, filename: str, work_mode: str, iv=None, cfb_mode=ENCRYPT):
        f = open(file=filename, mode='rb')
        if self.mode == ENCRYPT:
            w = open(file=work_mode + '_' + filename, mode='wb+')
        else:
            w = open(file='de' + '_' + filename, mode='wb+')
        data = f.read()
        res = b''
        if work_mode.lower() == 'ofb':
            res = bytes(self.ofb(data, iv))
        if work_mode.lower() == 'cbc':
            res = bytes(self.cbc(data, iv))
        if work_mode.lower() == 'ecb':
            res = bytes(self.ecb(data))
        if work_mode.lower() == 'cfb':
            res = bytes(self.cfb(data, iv, cfb_mode))
        w.write(res)


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


def input_bytes():
    bytes_str = input().strip().replace('\n', '').replace('\r', '')
    if bytes_str[:2] == '0x':
        bytes_str = bytes_str[2:]
    res = []
    for i in range(0, len(bytes_str), 2):
        res.append(int(bytes_str[i:i + 2], 16))
    return res


def input_bytes():
    bytes_str = input().strip().replace('\n', '').replace('\r', '')
    if bytes_str[:2] == '0x':
        bytes_str = bytes_str[2:]
    res = []
    for i in range(0, len(bytes_str), 2):
        res.append(int(bytes_str[i:i + 2], 16))
    return res


if __name__ == '__main__':
    in_k = 0x9975af70c80e7c0dd06fcef50cf5d49f
    in_iv = 0xa8638d2fb23cc49206ede7c84532eaab
    k = ANY_TO_BYTES(in_k, 128)
    iv = ANY_TO_BYTES(in_iv, 128)
    sm4 = SM4(ENCRYPT, k)
    sm4.file_process('test.jpg', 'ofb', iv)
