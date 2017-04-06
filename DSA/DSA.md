

# 第十八章 DSA

## 18.1 DSA简介

       Digital Signature Algorithm (DSA)算法是一种公钥算法。其密钥由如下部分组成：

* p:     一个大素数，长度为L(64的整数倍)比特。

* q:     一个160比特素数。

* g:    $$g=h^{(p-1)/q }mod p$$，其中h小于p-1。
* x:    小于q。

* y:   $$y=g^xmod p$$

  其中x为私钥，y为公钥。p、q和g是公开信息(openssl中称为密钥参数)。

  ​DSA签名包括两部分，如下：

> $$r = (g^k mod p) mod q$$
>
> $$s = (k^{-1} (H(m) + xr)) mod q$$


​	其中，H(m)为摘要算法；
​	DSA验签如下：

> $$w = s^{-1} mod q$$
>
> $$u1 = (H(m) * w) mod q$$
>
> $$u2 = (rw) mod q$$
>
> $$v = ((g^{u1} * y^{u2}) mod p) mod q$$

​	如果v=r，则验证通过。

## 18.2  openssl的DSA实现

Openssl的DSA实现源码在crypto/dsa目录下。主要源码如下：

1. dsa_asn1.c

   DSA密钥参数(p、q和g)、DSA公钥（pub_key、p、q和g）以及DSA私钥(priv_key、pub_key、p、q和g)的DER编解码实现。

2. dsa_depr.c

   生成DSA密钥参数。

3. dsa_err.c

   DSA错误处理。

4. dsa_gen.c

   生成DSA密钥参数。

5. dsa_key.c

   根据DSA中的密钥参数产生公钥和私钥。

6. dsa_lib.c

   实现了DSA通用的一些函数。

7. dsa_ossl.c

   实现了一个DSA_METHOD，该DSA_METHOD为openssl默认的DSA方法，主要实现了如下三个回调函数：dsa_do_sign（签名）、dsa_sign_setup（根据密钥参数生成公私钥）和dsa_do_verify（验签）。

8. dsa_sign.c

   实现了DSA签名和根据密钥参数生成公私钥。

9. dsa_vrf.c

   实现了DSA验签。

## 18.3  DSA数据结构

​	DSA数据结构定义在crypto/dsa.h中，如下所示：

1. DSA_SIG

   签名值数据结构:

```cpp
typedef struct DSA_SIG_st {
    BIGNUM* r;
    BIGNUM* s;
} DSA_SIG;
```

​	签名结果包括两部分，都是大数。

2. DSA_METHOD

```cpp
struct dsa_method {
    const char* name;
    DSA_SIG* (*dsa_do_sign)(const unsigned char* dgst, int dlen, DSA* dsa);
    int (*dsa_sign_setup)(DSA* dsa, BN_CTX* ctx_in, BIGNUM** kinvp, BIGNUM** rp);
    int (*dsa_do_verify)(const unsigned char* dgst, int dgst_len, DSA_SIG* sig, DSA* dsa);
    /* 其他 */
    int (*dsa_paramgen)(DSA* dsa, int bits, unsigned char* seed, int seed_len, int* counter_ret,
                        unsigned long* h_ret, BN_GENCB* cb);
    int (*dsa_keygen)(DSA* dsa);
};
```

​	本结构是一个函数集合，DSA的各种计算都通过它来实现。drypto/dsa_ossl.c中实现了一个默认的DSA_METHOD。如果用户实现了自己的DSA_METHOD，通过调用DSA_set_default_method或DSA_set_method，用户可以让openssl采用自己的DSA计算函数。

       主要项意义如下：

* name：DSA_METHOD的名字；
* dsa_do_sign：签名算法函数；
* dsa_sign_setup：根据密钥参数生成公私钥的函数；
* dsa_do_verify：签名验证函数；
* dsa_paramgen：生成密钥参数函数；
* dsa_keygen：生成公私钥函数。

## 18.4  主要函数

1. DSA_do_sign

   数据签名。

2. DSA_do_verify

   签名验证。

3. DSA_dup_DH

   将DSA密钥转换为DH密钥。

4. DSA_new

   生成一个DSA数据结构，一般情况下，DSA_METHOD采用默认的openssl_dsa_meth方法。

5. DSA_free

   释放DSA数据结构。

6. DSA_generate_key

   根据密钥参数生成公私钥。

7. DSA_generate_parameters

   生成密钥参数。

8. DSA_get_default_method

   获取默认的DSA_METHOD。

9. DSA_get_ex_data

       获取扩展数据。

10.  DSA_new_method

    生成一个DSA结构。

11.  DSA_OpenSSL

    获取openssl_dsa_meth方法。

12.  DSA_print

       将DSA密钥信息输出到BIO中。

13. DSA_print_fp

       将DSA密钥信息输出到FILE中。

14. DSA_set_default_method

       设置默认的DSA_METHOD。

15.   DSA_set_ex_data

     设置扩展数据。

16.   DSA_set_method

     获取当前DSA的DSA_METHOD方法。

17.   DSA_SIG_new

       生成一个DSA_SIG签名值结构。

18. DSA_SIG_free

       释放DSA_SIG结构。

19. DSA_sign

       DSA签名。

20. DSA_sign_setup

       根据密钥参数生成公私钥。

21. DSA_size

       获取DSA密钥长度的字节数。

22. DSA_up_ref

       给DSA结构添加一个引用。

23. DSA_verify

       签名验证。

24. DSAparams_print

       将DSA密钥参数输出到bio。

25. DSAparams_print_fp

       将DSA密钥参数输出到FILE。

## 18.5  编程示例

### 18.5.1  密钥生成

```cpp
#include <openssl/dsa.h>
#include <string.h>
int main() {
    DSA* d;
    int ret, i;
    unsigned charseed[20];
    int counter = 2;
    unsigned longh;
    d = DSA_new();
    for (i = 0; i < 20; i++)
        memset(seed + i, i, 1);
    // ret=DSA_generate_parameters_ex(d, 512,seed, 20, &counter,&h,NULL);
    /* 生成密钥参数 */
    ret = DSA_generate_parameters_ex(d, 512, NULL, 0, NULL, NULL, NULL);
    if (ret != 1) {
        DSA_free(d);
        return -1;
    }
    /* 生成密钥 */
    ret = DSA_generate_key(d);
    if (ret != 1) {
        DSA_free(d);
        return -1;
    }
    DSA_print_fp(stdout, d, 0);
    DSA_free(d);
    return 0;
}
```

 输出：

```log
       priv:
           35:8f:e6:50:e7:03:3b:5b:ba:ef:0a:c4:bd:92:e8:
           74:9c:e5:57:6d
       pub:
           41:ea:ff:ac:e4:d0:e0:53:2e:cf:f0:c2:34:93:9c:
           bc:b3:d2:f7:50:5e:e3:76:e7:25:b6:43:ed:ac:7b:
           c0:31:7d:ea:50:92:ee:2e:34:38:fa:2d:a6:03:0c:
           4f:f5:89:4b:4b:30:ab:e2:e8:4d:e4:77:f7:e9:4f:
           60:88:2e:2a
       P:
           00:ab:8d:e8:b8:be:d1:89:e0:24:6d:4b:4e:cd:43:
           9d:22:36:00:6a:d7:dd:f2:2c:cd:ce:69:9e:5f:87:
           b4:6e:76:5f:e6:ef:74:7c:3b:11:5d:60:50:db:ce:
           00:7e:ea:1e:a9:94:69:69:8b:e1:fc:7f:2a:ca:c2:
           f0:e5:f8:63:c1
       Q:
           00:f8:68:d5:d5:4b:85:e6:a7:4f:98:08:bc:00:e2:
           34:2e:94:cd:31:43
       G:
           00:8c:1a:09:06:a7:63:4b:cb:e0:c2:85:79:9f:12:
           9d:ac:a7:34:3c:eb:9b:ab:4b:fe:54:c1:22:ff:49:
           ec:17:d1:38:77:f5:2e:85:f7:80:d1:ac:4c:1a:96:
           a1:88:a5:90:66:31:ed:6f:0b:00:f7:2e:df:79:6b:
           95:97:c4:8a:95
```

### 18.5.2  签名与验证

```cpp
#include <openssl/dsa.h>
#include <openssl/objects.h>
#include <string.h>
int main() {
    int ret;
    DSA* d;
    int i, bits = 1024, signlen, datalen, alg, nid;
    unsigned char data[100], signret[200];
    d = DSA_new();
    ret = DSA_generate_parameters_ex(d, 512, NULL, 0, NULL, NULL, NULL);
    if (ret != 1) {
        DSA_free(d);
        return -1;
    }
    ret = DSA_generate_key(d);
    if (ret != 1) {
        DSA_free(d);
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
        datalen = 20;
        nid = NID_md5;
    } else if (alg == 2) {
        datalen = 20;
        nid = NID_sha;
    } else if (alg == 3) {
        datalen = 20;
        nid = NID_sha1;
    } else if (alg == 4) {
        datalen = 20;
        nid = NID_md5_sha1;
    }
    ret = DSA_sign(nid, data, datalen, signret, &signlen, d);
    if (ret != 1) {
        printf("DSA_sign err!\n");
        DSA_free(d);
        return -1;
    }
    ret = DSA_verify(nid, data, datalen, signret, signlen, d);
    if (ret != 1) {
        printf("DSA_verify err!\n");
        DSA_free(d);
        return -1;
    }
    DSA_free(d);
    printf("test ok!\n");
    return 0;
}
```

