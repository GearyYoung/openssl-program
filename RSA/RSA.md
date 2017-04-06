# 第十七章 RSA

## 17.1  RSA介绍

​	RSA算法是一个广泛使用的公钥算法。其密钥包括公钥和私钥。它能用于数字签名、身份认证以及密钥交换。RSA密钥长度一般使用1024位或者更高。RSA密钥信息主要包括[1]：

* n：模数

* e：公钥指数

* d：私钥指数

* p：最初的大素数

* q：最初的大素数

* dmp1：$$e*dmp1 = 1 (mod (p-1))$$

* dmq1：$$e*dmq1 = 1 (mod (q-1))$$

* iqmp：$$q*iqmp = 1 (mod p )$$

  其中，公钥为n和e；私钥为n和d。在实际应用中，公钥加密一般用来协商密钥；私钥加密一般用来签名。

## 17.2  openssl的RSA实现

​	Openssl的RSA实现源码在crypto/rsa目录下。它实现了RSA PKCS1标准。主要源码如下：

1. rsa.h

   定义RSA数据结构以及RSA_METHOD，定义了RSA的各种函数。

2. rsa_asn1.c

   实现了RSA密钥的DER编码和解码，包括公钥和私钥。

3. rsa_chk.c

   RSA密钥检查。

4. rsa_eay.c

   Openssl实现的一种RSA_METHOD，作为其默认的一种RSA计算实现方式。此文件未实现rsa_sign、rsa_verify和rsa_keygen回调函数。

5. rsa_err.c

   RSA错误处理。

6. rsa_gen.c

   RSA密钥生成，如果RSA_METHOD中的rsa_keygen回调函数不为空，则调用它，否则调用其内部实现。

7. rsa_lib.c

   主要实现了RSA运算的四个函数(公钥/私钥，加密/解密)，它们都调用了RSA_METHOD中相应都回调函数。

8. rsa_none.c

   实现了一种填充和去填充。

9. rsa_null.c

   实现了一种空的RSA_METHOD。

10. rsa_oaep.c

   实现了oaep填充与去填充。

11. rsa_pk1.

   实现了pkcs1填充与去填充。

12. rsa_sign.c

   实现了RSA的签名和验签。

13. rsa_ssl.c

   实现了ssl填充。

14. rsa_x931.c

   实现了一种填充和去填充。

## 17.3  RSA签名与验证过程

RSA签名过程如下：

1. 计算用户数据摘要；

2. 构造X509_SIG结构并DER编码，其中包括了摘要算法以及摘要结果。

3. 对2. 的结果进行填充，填满RSA密钥长度字节数。比如1024位RSA密钥必须填满128字节。具体的填充方式由用户指定。

4. 对3. 的结果用RSA私钥加密。

RSA_eay_private_encrypt函数实现了3. 和4. 过程。

RSA验签过程是上述过程的逆过程，如下：

1. 对数据用RSA公钥解密，得到签名过程中2. 的结果。

2. 去除1. 结果的填充。

3. 从2. 的结果中得到摘要算法，以及摘要结果。

4. 将原数据根据3. 中得到摘要算法进行摘要计算。

5. 比较4. 与签名过程中1. 的结果。

RSA_eay_public_decrypt实现了1. 和2. 过程。

## 17.4  数据结构

​	RSA主要数据结构定义在crypto/rsa/rsa.h中：

### 17.4.1 RSA_METHOD

```cpp
struct rsa_meth_st {
    const char* name;
    int (*rsa_pub_enc)(int flen, const unsigned char* from, unsigned char* to, RSA* rsa,
                       int padding);
    int (*rsa_pub_dec)(int flen, const unsigned char* from, unsigned char* to, RSA* rsa,
                       int padding);
    int (*rsa_priv_enc)(int flen, const unsigned char* from, unsigned char* to, RSA* rsa,
                        int padding);
    int (*rsa_priv_dec)(int flen, const unsigned char* from, unsigned char* to, RSA* rsa,
                        int padding);
    /* 其他函数 */
    int (*rsa_sign)(int type, const unsigned char* m, unsigned int m_length, unsigned char* sigret,
                    unsigned int* siglen, const RSA* rsa);
    int (*rsa_verify)(int dtype, const unsigned char* m, unsigned int m_length,
                      unsigned char* sigbuf, unsigned int siglen, const RSA* rsa);
    int (*rsa_keygen)(RSA* rsa, int bits, BIGNUM* e, BN_GENCB* cb);
};
```

​	 主要项说明：

* name：RSA_METHOD名称；

* rsa_pub_enc：公钥加密函数，padding为其填充方式，输入数据不能太长，否则无法填充；

* rsa_pub_dec：公钥解密函数，padding为其去除填充的方式，输入数据长度为RSA密钥长度的字节数；

* rsa_priv_enc：私钥加密函数，padding为其填充方式，输入数据长度不能太长，否则无法填充；

* rsa_priv_dec：私钥解密函数，padding为其去除填充的方式，输入数据长度为RSA密钥长度的字节数；

* rsa_sign：签名函数；

* rsa_verify：验签函数；

* rsa_keygen：RSA密钥对生成函数。

  用户可实现自己的RSA_METHOD来替换openssl提供的默认方法。

### 17.4.2  RSA

​	RSA数据结构中包含了公/私钥信息（如果仅有n和e，则表明是公钥. ，定义如下：

```cpp
struct rsa_st {
    /* 其他 */
    const RSA_METHOD* meth;
    ENGINE* engine;
    BIGNUM* n;
    BIGNUM* e;
    BIGNUM* d;
    BIGNUM* p;
    BIGNUM* q;
    BIGNUM* dmp1;
    BIGNUM* dmq1;
    BIGNUM* iqmp;
    CRYPTO_EX_DATA ex_data;
    int references;
    /* 其他数据项 */
};
```

各项意义：

* meth：RSA_METHOD结构，指明了本RSA密钥的各种运算函数地址；
* engine：硬件引擎；
* n，e，d，p，q，dmp1，dmq1，iqmp：RSA密钥的各个值；
* ex_data：扩展数据结构，用于存放用户数据；
* references：RSA结构引用数。

## 17.5  主要函数

1. `RSA_check_key`

   检查RSA密钥。

2. `RSA_new`

   生成一个RSA密钥结构，并采用默认的`rsa_pkcs1_eay_meth` RSA_METHOD方法。

3. `RSA_free`

   释放RSA结构。

4. `RSA *RSA_generate_key(int bits, unsigned long e_value, void (*callback)(int,int,void *), void *cb_arg)`

   生成RSA密钥，bits是模数比特数，e_value是公钥指数e，callback回调函数由用户实现，用于干预密钥生成过程中的一些运算，可为空。

5. RSA_get_default_method

   获取默认的RSA_METHOD，为rsa_pkcs1_eay_meth。

6. RSA_get_ex_data

   获取扩展数据。

7. RSA_get_method

   获取RSA结构的RSA_METHOD。

8. 各种填充方式函数

```cpp
RSA_padding_add_none
RSA_padding_add_PKCS1_OAEP
RSA_padding_add_PKCS1type1（私钥加密的填充.
RSA_padding_add_PKCS1type2（公钥加密的填充.
RSA_padding_add_SSLv23
```

9. 各种去除填充函数

```cpp
RSA_padding_check_none
RSA_padding_check_PKCS1_OAEP
RSA_padding_check_PKCS1type1
RSA_padding_check_PKCS1type2
RSA_padding_check_SSLv23
RSA_PKCS1_SSLeay
```

10.   `int RSA_print(BIO *bp, const RSA *x, int off)`

     将RSA信息输出到BIO中，off为输出信息在BIO中的偏移量，比如是屏幕BIO，则表示打印信息的位置离左边屏幕边缘的距离。

11.   `int DSA_print_fp(FILE *fp, const DSA *x, int off)`

     将RSA信息输出到FILE中，off为输出偏移量。

12.   RSA_public_decrypt

     RSA公钥解密。

13.   RSA_public_encrypt

     RSA公钥加密。

14.   RSA_set_default_method/ RSA_set_method

     设置RSA结构中的method，当用户实现了一个RSA_METHOD时，调用此函数来设置，使RSA运算采用用户的方法。

15.   RSA_set_ex_data

     设置扩展数据。

16.   RSA_sign

     RSA签名。

17.   RSA_sign_ASN1_OCTET_STRING

     另外一种RSA签名，不涉及摘要算法，它将输入数据作为ASN1_OCTET_STRING进行DER编码，然后直接调用RSA_private_encrypt进行计算。

18.   RSA_size

     获取RSA密钥长度字节数。

19.   RSA_up_ref

     给RSA密钥增加一个引用。

20.   RSA_verify

     RSA验证。

21.   RSA_verify_ASN1_OCTET_STRING

     另一种RSA验证，不涉及摘要算法，与RSA_sign_ASN1_OCTET_STRING对应。

22.   RSAPrivateKey_asn1_meth

     获取RSA私钥的ASN1_METHOD，包括i2d、d2i、new和free函数地址。

23.   RSAPrivateKey_dup

     复制RSA私钥。

24.   RSAPublicKey_dup

     复制RSA公钥。

## 17.6  编程示例

### 17.6.1  密钥生成

```cpp
#include <openssl/rsa.h>
int main() {
    RSA* r;
    int bits = 512, ret;
    unsigned longe = RSA_3;
    BIGNUM* bne;
    r = RSA_generate_key(bits, e, NULL, NULL);
    RSA_print_fp(stdout, r, 11);
    RSA_free(r);
    bne = BN_new();
    ret = BN_set_word(bne, e);
    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if (ret != 1) {
        printf("RSA_generate_key_ex err!\n");
        return -1;
    }
    RSA_free(r);
    return 0;
}
```

​	说明：调用RSA_generate_key和RSA_generate_key_ex函数生成RSA密钥，调用RSA_print_fp打印密钥信息。

```log
输出：
       Private-Key: (512 bit)
       modulus:
           00:d0:93:40:10:21:dd:c2:0b:6a:24:f1:b1:d5:b5:
           77:79:ed:a9:a4:10:66:6e:88:d6:9b:0b:4c:91:7f:
           23:6f:8f:0d:9e:9a:b6:7c:f9:47:fc:20:c2:12:e4:
           b4:d7:ab:66:3e:73:d7:78:00:e6:5c:98:35:29:69:
           c2:9b:c7:e2:c3
       publicExponent: 3 (0x3)
       privateExponent:
           00:8b:0c:d5:60:16:93:d6:b2:46:c3:4b:cb:e3:ce:
           4f:a6:9e:71:18:0a:ee:f4:5b:39:bc:b2:33:0b:aa:
           17:9f:b3:7e:f0:0f:2a:24:b6:e4:73:40:ba:a0:65:
           d3:19:0f:c5:b5:4f:59:51:e2:df:9c:83:47:da:8d:
           84:0f:26:df:1b
       prime1:
           00:f7:4c:fb:ed:32:a6:74:5c:2d:6c:c1:c5:fe:3a:
           59:27:6a:53:5d:3e:73:49:f9:17:df:43:79:d4:d0:
           46:2f:0d
       prime2:
           00:d7:e9:88:0a:13:40:7c:f3:12:3d:60:85:f9:f7:
           ba:96:44:29:74:3e:b9:4c:f8:bb:6a:1e:1b:a7:b4:
           c7:65:0f
       exponent1:
           00:a4:dd:fd:48:cc:6e:f8:3d:73:9d:d6:83:fe:d1:
           90:c4:f1:8c:e8:d4:4c:db:fb:65:3f:82:51:38:8a:
           d9:74:b3
       exponent2:
           00:8f:f1:05:5c:0c:d5:a8:a2:0c:28:eb:03:fb:fa:
           7c:64:2d:70:f8:29:d0:dd:fb:27:9c:14:12:6f:cd:
           da:43:5f
       coefficient:
           00:d3:fa:ea:a0:21:7e:8a:e1:ab:c7:fd:e9:3d:cb:
           5d:10:96:17:69:75:cd:71:d5:e5:07:26:93:e8:35:
           ca:e3:49
```

### 17.6.2  RSA加解密运算

```cpp
#include <openssl/rsa.h>
#include <openssl/sha.h>
int main() {
    RSA* r;
    int bits = 1024, ret, len, flen, padding, i;
    unsigned longe = RSA_3;
    BIGNUM* bne;
    unsigned char *key, *p;
    BIO* b;
    unsigned char from[500], to[500], out[500];
    bne = BN_new();
    ret = BN_set_word(bne, e);
    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if (ret != 1) {
        printf("RSA_generate_key_ex err!\n");
        return -1;
    }
    /* 私钥i2d */
    b = BIO_new(BIO_s_mem());
    ret = i2d_RSAPrivateKey_bio(b, r);
    key = malloc(1024);
    len = BIO_read(b, key, 1024);
    BIO_free(b);
    b = BIO_new_file("rsa.key", "w");
    ret = i2d_RSAPrivateKey_bio(b, r);
    BIO_free(b);
    /* 私钥d2i */
    /* 公钥i2d */
    /* 公钥d2i */
    /* 私钥加密 */
    flen = RSA_size(r);
    printf("please select private enc padding : \n");
    printf("1.RSA_PKCS1_PADDING\n");
    printf("3.RSA_NO_PADDING\n");
    printf("5.RSA_X931_PADDING\n");
    scanf("%d", &padding);
    if (padding == RSA_PKCS1_PADDING)
        flen -= 11;
    else if (padding == RSA_X931_PADDING)
        flen -= 2;
    else if (padding == RSA_NO_PADDING)
        flen = flen;
    else {
        printf("rsa not surport !\n");
        return -1;
    }
    for (i = 0; i < flen; i++)
        memset(&from[i], i, 1);
    len = RSA_private_encrypt(flen, from, to, r, padding);
    if (len <= 0) {
        printf("RSA_private_encrypt err!\n");
        return -1;
    }
    len = RSA_public_decrypt(len, to, out, r, padding);
    if (len <= 0) {
        printf("RSA_public_decrypt err!\n");
        return -1;
    }
    if (memcmp(from, out, flen)) {
        printf("err!\n");
        return -1;
    }

    printf("please select public enc padding : \n");
    printf("1.RSA_PKCS1_PADDING\n");
    printf("2.RSA_SSLV23_PADDING\n");
    printf("3.RSA_NO_PADDING\n");
    printf("4.RSA_PKCS1_OAEP_PADDING\n");
    scanf("%d", &padding);
    flen = RSA_size(r);
    if (padding == RSA_PKCS1_PADDING)
        flen -= 11;
    else if (padding == RSA_SSLV23_PADDING)
        flen -= 11;
    else if (padding == RSA_X931_PADDING)
        flen -= 2;
    else if (padding == RSA_NO_PADDING)
        flen = flen;
    else if (padding == RSA_PKCS1_OAEP_PADDING)
        flen = flen - 2 * SHA_DIGEST_LENGTH - 2;
    else {
        printf("rsa not surport !\n");
        return -1;
    }
    for (i = 0; i < flen; i++)
        memset(&from[i], i + 1, 1);
    len = RSA_public_encrypt(flen, from, to, r, padding);
    if (len <= 0) {
        printf("RSA_public_encrypt err!\n");
        return -1;
    }
    len = RSA_private_decrypt(len, to, out, r, padding);
    if (len <= 0) {
        printf("RSA_private_decrypt err!\n");
        return -1;
    }
    if (memcmp(from, out, flen)) {
        printf("err!\n");
        return -1;
    }
    printf("test ok!\n");
    RSA_free(r);
    return 0;
}
```

### 17.6.3  签名与验证

```cpp
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <string.h>
int main() {
    int ret;
    RSA* r;
    int i, bits = 1024, signlen, datalen, alg, nid;
    unsigned longe = RSA_3;
    BIGNUM* bne;
    unsigned char data[100], signret[200];
    bne = BN_new();
    ret = BN_set_word(bne, e);
    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if (ret != 1) {
        printf("RSA_generate_key_ex err!\n");
        return -1;
    }
    for (i = 0; i < 100; i++)
        memset(&data[i], i + 1, 1);
    printf("please select digest alg: \n");
    printf("1.NID_md5\n");
    printf("2.NID_sha\n");
    printf("3.NID_sha1\n");
    printf("4.NID_md5_sha1\n");
    scanf("%d", &alg);
    if (alg == 1) {
        datalen = 55;
        nid = NID_md5;
    } else if (alg == 2) {
        datalen = 55;
        nid = NID_sha;
    } else if (alg == 3) {
        datalen = 55;
        nid = NID_sha1;
    } else if (alg == 4) {
        datalen = 36;
        nid = NID_md5_sha1;
    }
    ret = RSA_sign(nid, data, datalen, signret, &signlen, r);
    if (ret != 1) {
        printf("RSA_sign err!\n");
        RSA_free(r);
        return -1;
    }
    ret = RSA_verify(nid, data, datalen, signret, signlen, r);
    if (ret != 1) {
        printf("RSA_verify err!\n");
        RSA_free(r);
        return -1;
    }
    RSA_free(r);
    printf("test ok!\n");
    return 0;
}
```

​	*注意：本示例并不是真正的数据签名示例，因为没有做摘要计算。*

​	`ret=RSA_sign(nid,data,datalen,signret,&signlen,r)`将需要运算的数据放入X509_ALGOR数据结构并将其DER编码，对编码结果做RSA_PKCS1_PADDING再进行私钥加密。

​	被签名数据应该是摘要之后的数据，而本例没有先做摘要，直接将数据拿去做运算。因此datalen不能太长，要保证RSA_PKCS1_PADDING私钥加密运算时输入数据的长度限制。`ret=RSA_verify(nid,data,datalen,signret,signlen,r)`用来验证签名。
