# 第十九章 DH

## 19.1  DH算法介绍

​	DH算法是W.Diffie和M.Hellman提出的。此算法是最早的公钥算法。它实质是一个通信双方进行密钥协商的协议：两个实体中的任何一个使用自己的私钥和另一实体的公钥，得到一个对称密钥，这一对称密钥其它实体都计算不出来。DH算法的安全性基于有限域上计算离散对数的困难性。离散对数的研究现状表明：所使用的DH密钥至少需要1024位，才能保证有足够的中、长期安全。

​	首先，发送方和接收方设置相同的大数数n和g，这两个数不是保密的，他们可以通过非安全通道来协商这两个素数；

       接着，他们用下面的方法协商密钥：

* 发送方选择一个大随机整数x，计算$$X= g^x mod n $$，发送X给接收者；

* 接收方选择一个大随机整数y，计算$$Y = g^y mod n $$，发送Y给发送方；

* 双方计算密钥：发送方密钥为$$k1=Y^x mod n$$，接收方密钥为$$k2=X^y mod n$$。

  其中$$k1=k2=g^{(xy)} mod n$$。

​	其他人可以知道n、g、X和Y，但是他们不能计算出密钥，除非他们能恢复x和y。DH算法不能抵御中间人攻击，中间人可以伪造假的X和Y分别发送给双方来获取他们的秘密密钥，所以需要保证X和Y的来源合法性。

## 19.2  openssl的DH实现

​	Openssl的DH实现在crypto/dh目录中。各个源码如下：

1. dh.h

   定义了DH密钥数据结构以及各种函数。

2. dh_asn1.c

   DH密钥参数的DER编解码实现。

3. dh_lib.c

   实现了通用的DH函数。

4. dh_gen.c

   实现了生成DH密钥参数。

5. dh_key.c

   实现openssl提供的默认的DH_METHOD，实现了根据密钥参数生成DH公私钥，以及根据DH公钥(一方)以及DH私钥(另一方)来生成一个共享密钥，用于密钥交换。

6. dh_err.c

   实现了DH错误处理。

7. dh_check.c

   实现了DH密钥检查。

## 19.3数据结构

​	DH数据结构定义在crypto/dh/dh.h中，主要包含两项，如下：

1. DH_METHOD

```cpp
struct dh_method {
    const char* name;
    int (*generate_key)(DH* dh);
    int (*compute_key)(unsigned char* key, const BIGNUM* pub_key, DH* dh);
    int (*bn_mod_exp)(const DH* dh, BIGNUM* r, const BIGNUM* a, const BIGNUM* p, const BIGNUM* m,
                      BN_CTX* ctx, BN_MONT_CTX* m_ctx);
    int (*init)(DH* dh);
    int (*finish)(DH* dh);
    int flags;
    char* app_data;
    int (*generate_params)(DH* dh, int prime_len, int generator, BN_GENCB* cb);
};
```

​	DH_METHOD指明了一个DH密钥所有的计算方法函数。用户可以实现自己的DH_METHOD来替换openssl提供默认方法。各项意义如下：

* name：DH_METHOD方法名称。
* generate_key：生成DH公私钥的函数。
* compute_key：根据对方公钥和己方DH密钥来生成共享密钥的函数。
* bn_mod_exp：大数模运算函数，如果用户实现了它，生成DH密钥时，将采用用户实现的该回调函数。用于干预DH密钥生成。
* init：初始化函数。
* finish：结束函数。
* flags：用于记录标记。
* app_data：用于存放应用数据。
* generate_params：生成DH密钥参数的回调函数，生成的密钥参数是可以公开的。

2. DH

```cpp
struct dh_st {
    /* 其他 */
    BIGNUM* p;
    BIGNUM* g;
    long length; /* optional */
    BIGNUM* pub_key;
    BIGNUM* priv_key;
    int references;
    CRYPTO_EX_DATA ex_data;
    const DH_METHOD* meth;
    ENGINE* engine;
    /* 其他 */
};
```

* p、g、length：DH密钥参数；
* pub_key：DH公钥；
* priv_key：DH私钥；
* references：引用；
* ex_data：扩展数据；
* meth：DH_METHOD，本DH密钥的各种计算方法，明确指明了DH的各种运算方式；
* engine：硬件引擎。

## 19.4  主要函数

1. DH_new

   生成DH数据结构，其DH_METHOD采用openssl默认提供的。

2. DH_free

   释放DH数据结构。

3. DH_generate_parameters

   生成DH密钥参数。

4. DH_generate_key

   生成DH公私钥。

5. DH_compute_key

   计算共享密钥，用于数据交换。

6. DH_check

   检查DH密钥。

7. DH_get_default_method

   获取默认的DH_METHOD，该方法是可以由用户设置的。

8. DH_get_ex_data

   获取DH结构中的扩展数据。

9. DH_new_method

   生成DH数据结构。

10. DH_OpenSSL

    获取openssl提供的DH_METHOD。

11. DH_set_default_method

    设置默认的DH_METHOD方法，当用户实现了自己的DH_METHOD时，可调用本函数来设置，控制DH各种计算。

12. DH_set_ex_data

    获取扩展数据。

13. DH_set_method

    替换已有的DH_METHOD。

14. DH_size

    获取DH密钥长度的字节数。

15. DH_up_ref

    增加DH结构的一个引用。

16. DHparams_print

    将DH密钥参数输出到bio中。

17. DHparams_print_fp

    将DH密钥参数输出到FILE中。

## 19.5  编程示例

```cpp
#include <memory.h>
#include <openssl/dh.h>
int main() {
    DH *d1, *d2;
    BIO* b;
    int ret, size, i, len1, len2;
    charsharekey1[128], sharekey2[128];
    /* 构造DH数据结构 */
    d1 = DH_new();
    d2 = DH_new();
    /* 生成d1的密钥参数，该密钥参数是可以公开的 */
    ret = DH_generate_parameters_ex(d1, 64, DH_GENERATOR_2, NULL);
    if (ret != 1) {
        printf("DH_generate_parameters_ex err!\n");
        return -1;
    }
    /* 检查密钥参数 */
    ret = DH_check(d1, &i);
    if (ret != 1) {
        printf("DH_check err!\n");
        if (i & DH_CHECK_P_NOT_PRIME)
            printf("p value is not prime\n");
        if (i & DH_CHECK_P_NOT_SAFE_PRIME)
            printf("p value is not a safe prime\n");
        if (i & DH_UNABLE_TO_CHECK_GENERATOR)
            printf("unable to check the generator value\n");
        if (i & DH_NOT_SUITABLE_GENERATOR)
            printf("the g value is not a generator\n");
    }
    printf("DH parameters appear to be ok.\n");
    /* 密钥大小 */
    size = DH_size(d1);
    printf("DH key1 size : %d\n", size);
    /* 生成公私钥 */
    ret = DH_generate_key(d1);
    if (ret != 1) {
        printf("DH_generate_key err!\n");
        return -1;
    }
    /* p和g为公开的密钥参数，因此可以拷贝 */
    d2->p = BN_dup(d1->p);
    d2->g = BN_dup(d1->g);
    /* 生成公私钥,用于测试生成共享密钥 */
    ret = DH_generate_key(d2);
    if (ret != 1) {
        printf("DH_generate_key err!\n");
        return -1;
    }
    /* 检查公钥 */
    ret = DH_check_pub_key(d1, d1->pub_key, &i);
    if (ret != 1) {
        if (i & DH_CHECK_PUBKEY_TOO_SMALL)
            printf("pub key too small \n");
        if (i & DH_CHECK_PUBKEY_TOO_LARGE)
            printf("pub key too large \n");
    }
    /* 计算共享密钥 */
    len1 = DH_compute_key(sharekey1, d2->pub_key, d1);
    len2 = DH_compute_key(sharekey2, d1->pub_key, d2);
    if (len1 != len2) {
        printf("生成共享密钥失败1\n");
        return -1;
    }
    if (memcmp(sharekey1, sharekey2, len1) != 0) {
        printf("生成共享密钥失败2\n");
        return -1;
    }
    printf("生成共享密钥成功\n");
    b = BIO_new(BIO_s_file());
    BIO_set_fp(b, stdout, BIO_NOCLOSE);
    /* 打印密钥 */
    DHparams_print(b, d1);
    BIO_free(b);
    DH_free(d1);
    DH_free(d2);
    return 0;
}
```

​	本例主要演示了生成DH密钥以及密钥交换函数。