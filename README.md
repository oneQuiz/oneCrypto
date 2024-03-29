# oneCrypto 密码库



### oneCrypto.common

#### 内容

 常见的数学、编码运算。

- 大整数和字符串的相互转化
- 整数求逆
- 快速模幂
- 扩欧运算
- 中国剩余定理

#### 测试

![image-20220614211604139](photo/image-20220614211604139.png)

![image-20220614211755185](photo/image-20220614211755185.png)



### oneCrypto.primes

#### 内容

素数和强素数运算。

- Miller-Rabin素性检验
- 强素数检验
- 按比特长度随机获取素数
- 按比特长度随机获取强素数

#### 测试

![image-20220614212028277](photo/image-20220614212028277.png)

![image-20220614212103813](photo/image-20220614212103813.png)

### oneCrypto.ECC

#### 内容

椭圆曲线运算。

- 基于 ECC 的四则运算
- 椭圆曲线上的加解密算法

#### 测试

见 `oneCrypto.SM2`。

### oneCrypto.SM2

#### 内容

国家标准椭圆曲线公钥加密算法，支持输入检测。

- 加密算法
- 签名算法

#### 测试

![image-20220614212603459](photo/image-20220614212603459.png)

![image-20220614212624185](photo/image-20220614212624185.png)

![image-20220614212643602](photo/image-20220614212643602.png)

### oneCrypto.SM3

#### 内容

国密 SM3 密码杂凑算法。

#### 测试

![image-20220614212834875](photo/image-20220614212834875.png)

### oneCrypto.SM4

#### 内容

国家标准分组密码，支持输入检测。

- 基本加解密运算
- PKCS#7 填充模式下的 ECB 工作模式加解密
- PKCS#7 填充模式下的 CBC 工作模式加解密
- OFB、CFB 工作模式加解密
- 以上工作模式的文件加解密

#### 测试

<img src="photo/image-20220614213557730.png" alt="image-20220614213557730" style="zoom:67%;" />

![image-20220614213641997](photo/image-20220614213641997.png)

<img src="photo/image-20220614213627154.png" alt="image-20220614213627154" style="zoom:67%;" />

![image-20220614213651039](photo/image-20220614213651039.png)

##### test

<img src="photo/image-20220614213740374.png" alt="image-20220614213740374" style="zoom:50%;" />

##### ofb_test

<img src="photo/image-20220614213817491.png" alt="image-20220614213817491" style="zoom:50%;" />

##### de_ofb_test

<img src="photo/image-20220614214140290.png" alt="image-20220614214140290" style="zoom:50%;" />

