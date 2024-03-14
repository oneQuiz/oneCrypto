"""
运行此脚本即完成 oneCrypto库的测试
"""
# 素数和强素数运算
from oneCrypto.prime import *

a = getPrime(1024)
b = getStrongPrime(512)
print(isPrime(a), isStrongPrime(b))
print('a:', a)
print('b:', b)
# 常见的数学、编码运算
from oneCrypto.common import *

c = invmod(a, b)
d = fastpow(a, 100, b)
s = 'test'
n = str2int(s)
s = int2str(n)
print('c:', c)
print('d:', d)
print('n:', n)
print('s:', s)
# 分组密码算法选择国密算法SM4，有输入检测
# 支持ecb、cbc、ofb、cfb四种工作模式
# 支持文件加解密操作
from oneCrypto.SM4 import *

_k = 0x999999999999
k = 0x9975af70c80e7c0dd06fcef50cf5d49f
iv = ANY_TO_BYTES(0xa8638d2fb23cc49206ede7c84532eaab, 128)
try:
    wronglength_sm4 = SM4(ENCRYPT, ANY_TO_BYTES(_k, 6))
except:
    print('有输入检测')
sm4 = SM4(ENCRYPT, ANY_TO_BYTES(k, 128))
# ofb模式
sm4.file_process('test', 'ofb', iv)
sm4.chmod(DECRYPT)
sm4.file_process('ofb_test', 'ofb', iv)
# cfb模式
sm4.chmod(ENCRYPT)
sm4.file_process('test', 'cfb', iv, cfb_mode=DECRYPT)
sm4.chmod(DECRYPT)
sm4.file_process('cfb_test', 'cfb', iv, cfb_mode=DECRYPT)
# cbc模式
sm4.chmod(ENCRYPT)
sm4.file_process('test', 'cbc', iv)
sm4.chmod(DECRYPT)
sm4.file_process('cbc_test', 'cbc', iv)
# ecb模式
sm4.chmod(ENCRYPT)
sm4.file_process('test', 'ecb', iv)
sm4.chmod(DECRYPT)
sm4.file_process('ecb_test', 'ecb', iv)
print('SM4 Encryption is done，check the file \"*_test\" and \"de_*_test.')
# 公钥密码算法选择国密算法SM2，有输入检测
from oneCrypto.SM2 import *

p = 60275702009245096385686171515219896416297121499402250955537857683885541941187
a = 54492052985589574080443685629857027481671841726313362585597978545915325572248
b = 45183185393608134601425506985501881231876135519103376096391853873370470098074
g = (
    29905514254078361236418469080477708234343499662916671209092838329800180225085,
    2940593737975541915790390447892157254280677083040126061230851964063234001314
)
p_pub = (
    30466142855137288468788190552058120832437161821909553502398316083968243039754,
    53312363470992020232197984648603141288071418796825192480967103513769615518274
)
d_pri = 10081045928272161671685667373292278982781750263333427527755954552719521025440
s = bytes.fromhex('656e6372797074696f6e207374616e64617264')
id_A = 'ALICE123@YAHOO.COM'.encode('utf-8')
ecc = ECC(a, b, p)
sm2 = SM2(ecc, g, p_pub=p_pub, d_pri=d_pri, id_A=id_A)
r = 34550576952843389977837539438321907097625575044301827052096699664811526290255
c = sm2.encrypt(s, r)
print('s:', '656e6372797074696f6e207374616e64617264')
print('c:', c.hex())
print('s:', sm2.decrypt(c).hex())
# 数字签名算法选择国密算法SM2
sm2.p_pub = (
    4927346340877997421592888003129352901369751434954921663604743238822873158794,
    56090775331359075302546016414740579914612192649583459645010750108260086900823
)
sm2.g = (
    29905514254078361236418469080477708234343499662916671209092838329800180225085,
    2940593737975541915790390447892157254280677083040126061230851964063234001314
)
sm2.ord_g = 60275702009245096385686171515219896415919644698453424055561665251330296281527
sm2.d_pri = 8387551947784012071400071471596312053542870740821494713120726177333060924003
m = 'message digest'.encode('utf-8')
k = 8387551947784012071400071471596312053542870740821494713120726177333060924003
r, s = sm2.sign(m, k)
print(f"sign:\n\tr:{r}\n\ts:{s}")
print(f"verify:{sm2.verify(m,r,s)}")

print("oneCrypto is a rookie cryptography module oneQuiz ")
