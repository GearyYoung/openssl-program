# 第二十三章 Engine

## 23.1  Engine概述

​	Openssl硬件引擎(Engine）能够使用户比较容易地将自己的硬件加入到openssl中去，替换其提供的软件算法。一个Engine提供了密码计算中各种计算方法的集合，它用于控制openssl的各种密码计算。

## 23.2  Engine支持的原理

​	Openssl中的许多数据结构不仅包含数据本身，还包含各种操作，并且这些操作是可替换的。Openssl中这些结构集合一般叫做XXX_METHOD，有DSO_METHOD、DSA_METHOD、EC_METHOD、ECDH_METHOD、ECDSA_METHOD、DH_METHOD、RAND_METHOD、RSA_METHOD、EVP_CIPHER和EVP_MD等。以RSA结构为例(crypto/rsa/rsa.h)，RSA结构不仅包含了大数n、e、d和p等等数据项目，还包含一个RSA_METHOD回调函数集合。该方法给出了RSA各种运算函数。

​	对于各种数据类型，要进行计算必须至少有一个可用的方法(XXX_METHOD)。因此，openssl对各种类型都提供了默认的计算方法(软算法)。如果用户实现了自己的XXX_METHOD，那么就能替换openssl提供的方法，各种计算由用户自己控制。硬件Engine就是这种原理。根据需要，一个硬件Engine可实现自己的RAND_METHOD、RSA_METHOD、EVP_CIPHER、DSA_METHOD、DH_METHOD、ECDH_METHOD和EVP_MD等，来替换对应软算法的METHOD。

## 23.3  Engine数据结构

​	Engine数据结构定义在crypto/engine/eng_int.h文件中，是对用户透明的数据结构，如下：

```cpp
struct engine_st {
    const char* id;                  // Engine标识；
    const char* name;                // Engine的名字；
    const RSA_METHOD* rsa_meth;      // RSA方法集合；
    const DSA_METHOD* dsa_meth;      // DSA方法集合；
    const DH_METHOD* dh_meth;        // DH方法集合；
    const ECDH_METHOD* ecdh_meth;    // ECDH方法结合；
    const ECDSA_METHOD* ecdsa_meth;  // ECDSA方法集合；
    const RAND_METHOD* rand_meth;    //随机数方法集合；
    const STORE_METHOD* store_meth;  //存储方法集合；
    ENGINE_CIPHERS_PTR
        ciphers;  //对称算法选取函数。硬件一般会支持多种对称算法，该回调函数用来从用户实现的多个对称算法中根据某种条件(一般是算法nid)来选择其中的一种；
    ENGINE_DIGESTS_PTR
        digests;                       //摘要算法选取函数。该回调函数用来从用户实现的多个摘要算法中根据某种条件(一般是算法nid)来选择其中的一种；
    ENGINE_GEN_INT_FUNC_PTR destroy;   //销毁引擎函数；
    ENGINE_GEN_INT_FUNC_PTR init;      //初始化引擎函数；
    ENGINE_GEN_INT_FUNC_PTR finish;    //完成回调函数；
    ENGINE_CTRL_FUNC_PTR ctrl;         //控制函数；
    ENGINE_LOAD_KEY_PTR load_privkey;  //加载私钥函数；
    ENGINE_LOAD_KEY_PTR load_pubkey;   //加载公钥函数；
    /* 其他项 */
    CRYPTO_EX_DATA ex_data;  //扩展数据结构，可用来存放用户数据；
    struct engine_st* prev;  //用于构建Engine链表，openssl中的硬件Engine可能不止一个。
    struct engine_st* next;  //同上
};
```

​	上述这些函数，用户根据应用的需求来实现其中的一种或多种。

## 23.4  openssl 的Engine源码

​	Openssl的Engine源码分为四类：

1. 核心实现

   在crypto/engine目录下，是其核心实现。当同时有多个硬件Engine时，openssl分别为cipher对称算法(tb_cipher.c)、dh算法(tb_dh.c)、digest摘要算法(tb_digest.c)、dsa算法(tb_dsa.c)、ecdh算法(tb_ecdh.c)、ecdsa算法(tb_ecdsa.c)、rand随机数算法(tb_rand.c)、rsa算法(tb_rsa.c)和存储方式(tb_store.c)维护一个哈希表。所有用户实现的硬件Engine都注册在这些全局的哈希表中。同时，用户使用的时候，能够指定各种算法默认的硬件Engine。

2. 内置硬件Engine

   源码位于engines目录，实现了一些硬件Engine。

3. 范例

   源码位于demos/engines目录下，供用户学习参考。

4. 分散于其他各个运算模块用于支持Engine

   各个运算模块都支持Engine，当提供了Engine时，将会采用Engine中的算法。

## 23.5  Engine函数

​	主要函数如下：

1. ENGINE_add

   将Engine加入全局到链表中。

2. ENGINE_by_id

   根据id来获取Engine。

3. ENGINE_cleanup

   清除所有Engine数据。

4. `const EVP_CIPHER *ENGINE_get_cipher(ENGINE *e, int nid)`

   根据指定的硬件Engine以及对称算法的nid，获取Engine实现的对应的  EVP_CIPHER，用于对称计算。

5. ENGINE_get_cipher_engine

   根据对称算法nid来获取Engine。

6. ENGINE_get_ciphers/ENGINE_set_ciphers

   获取/设置指定Engine的对称算法选取函数地址，该函数用于从Engine中选择一种对称算法。

7. ENGINE_get_ctrl_function

   获取Engine的控制函数地址。

8. `const DH_METHOD *ENGINE_get_DH(const ENGINE *e)`

   获取Engine的DH_METHOD。

9. `const EVP_MD *ENGINE_get_digest(ENGINE *e, int nid)`

   根据Engine和摘要算法nid来获取Engine中实现的摘要方法EVP_MD。

10. `ENGINE *ENGINE_get_digest_engine(int nid)`

    根据摘要算法nid来获取Engine。

11. `ENGINE_get_digests/ENGINE_set_digests`

    获取/设置指定Engine的摘要算法选取函数地址，该函数用于从Engine中选择一种摘要算法。

12. `const DSA_METHOD *ENGINE_get_DSA(const ENGINE *e)`

    获取Engine的DSA方法。

13. `int ENGINE_register_XXX(ENGINE *e)`

    注册函数，将某一个Engine添加到对应方法的哈希表中。

14. `void ENGINE_unregister_XXX(ENGINE *e)`

    将某一个Engine从对应的哈希表中删除。

15. `void ENGINE_register_all_XXX(void)`

    将所有的Engine注册到对应方法的哈希表中。

16. ENGINE_set_default_XXXX

    设置某Engine为对应XXXX方法的默认Engine。

17. ENGINE_get_default_XXXX

    获取XXXX方法的默认Engine。

18. ENGINE_load_XXXX

    加载某种Engine。

19. ENGINE_get_RAND/ENGINE_set_RAND

    获取/设置Engine的随机数方法。

20. ENGINE_get_RSA/ENGINE_set_RSA

    获取/设置Engine的RSA方法。

21. ENGINE_get_first/ENGINE_get_next/ENGINE_get_prev/ENGINE_get_last

    Engine链表操作函数。

22. ENGINE_set_name/ENGINE_get_name

    设置/获取Engine名字。

23. ENGINE_set_id/ENGINE_get_id

    设置/获取Engine的id。

24. `int ENGINE_set_default(ENGINE *e, unsigned int flags)`

    根据flags将e设置为各种方法的默认Engine。

25. ENGINE_set_XXX_function

    设置Engine中XXX对应的函数。

26. ENGINE_get_XXX_function

    获取Engine中XXX对应的函数。

27. ENGINE_ctrl

    Engine控制函数。

28. ENGINE_get_ex_data/ENGINE_set_ex_data

    获取/设置Engine的扩展数据。

29. ENGINE_init/ENGINE_finish

    Engine初始化/结束。

30. ENGINE_up_ref

    给Engine增加一个引用。

31. ENGINE_new/ENGINE_free

    生成/释放一个Engine数据结构。

32. ENGINE_register_complete

    将给定的Engine，对于每个方法都注册一遍。

33. ENGINE_register_all_complete

    将所有的Engine，对于每个方法都注册一遍。

## 23.6  实现Engine示例

​	以下的示例演示了采用Engine机制，来改变openssl的各种运算行为。实现的Engine方法有：随机数方法、对称算法、摘要算法以及RSA运算算法。其中，RSA计算中，密钥ID存放在Engine的扩展数据结构中。

```cpp
#include <openssl/engine.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
static int hw_get_random_bytes(unsigned char* buf, int num) {
    int i;
    printf("call hw_get_random_bytes\n");
    for (i = 0; i < num; i++)
        memset(buf++, i, 1);
    return 1;
}
/* 生成RSA密钥对 */
static int genrete_rsa_key(RSA* rsa, int bits, BIGNUM* e, BN_GENCB* cb) {
    printf("genrete_rsa_key \n");
    return 1;
}
/* RSA公钥加密 */
int rsa_pub_enc(int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding) {
    printf("call rsa_pub_enc \n");
    return 1;
}
/*RSA公钥解密 */
int rsa_pub_dec(int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding) {
    printf("call rsa_pub_enc \n");
    return 1;
}
/* RSA私钥加密 */
int rsa_priv_enc(int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding) {
    char* keyid;
    /* 获取私钥id */
    keyid = (char*)ENGINE_get_ex_data(rsa->engine, 0);
    printf("call rsa_pub_dec \n");
    printf("use key id :%d \n", keyid);
    return 1;
}
/* RSA私钥解密 */
int rsa_priv_dec(int flen, const unsigned char* from, unsigned char* to, RSA* rsa, int padding) {
    printf("call rsa_priv_dec \n");
    return 1;
}
/* RSA算法 */
RSA_METHOD hw_rsa = {"hw cipher", rsa_pub_enc, rsa_pub_dec, rsa_priv_enc,   rsa_priv_dec,
                     NULL,        NULL,        NULL,        NULL,           RSA_FLAG_SIGN_VER,
                     NULL,        NULL,        NULL,        genrete_rsa_key};
/* 随机数方法 */
static RAND_METHOD hw_rand = {
    NULL, hw_get_random_bytes, NULL, NULL, NULL, NULL,
};
/* Engine的id */
static const char* engine_hw_id = "ID_hw";
/* Engine的名字 */
static const char* engine_hw_name = "hwTest";
static int hw_init(ENGINE* e) {
    printf("call hw_init\n");
    return 1;
}
static int hw_destroy(ENGINE* e) {
    printf("call hw_destroy\n");
    return 1;
}
static int hw_finish(ENGINE* e) {
    printf("call hw_finish\n");
    return 0;
}
static EVP_PKEY* hw_load_privkey(ENGINE* e, const char* key_id, UI_METHOD* ui_method,
                                 void* callback_data) {
    /* 将密钥id放在ENGINE的扩展数据中 */
    int index;
    printf("call hw_load_privkey\n");
    index = 0;
    ENGINE_set_ex_data(e, index, (char*)key_id);
    return NULL;
}
#define HW_SET_RSA_PRIVATE_KEY 1
/* 实现自己的控制函数 */
static int hw_ctrl(ENGINE* e, int cmd, long i, void* p, void (*f)(void)) {
    switch (cmd) {
    case HW_SET_RSA_PRIVATE_KEY:
        hw_load_privkey(e, p, NULL, NULL);
        break;
    default:
        printf("err.\n");
        return -1;
    }
    return 0;
}
static EVP_PKEY* hw_load_pubkey(ENGINE* e, const char* key_id, UI_METHOD* ui_method,
                                void* callback_data) {
    printf("call hw_load_pubkey\n");
    return NULL;
}
static const ENGINE_CMD_DEFN hw_cmd_defns[] = {{ENGINE_CMD_BASE, "SO_PATH",
                                                "Specifies the path to the 'hw' shared library",
                                                ENGINE_CMD_FLAG_STRING},
                                               {0, NULL, NULL, 0}};
static int hw_init_key(EVP_CIPHER_CTX* ctx, const unsigned char* key, const unsigned char* iv,
                       int enc) {
    return 1;
}

static int hw_cipher_enc(EVP_CIPHER_CTX* ctx, unsigned char* out, const unsigned char* in,
                         unsigned int inl) {
    memcpy(out, in, inl);
    return 1;
}

/* 定义自己的des_ecb硬件算法*/
#include <openssl/objects.h>

static const EVP_CIPHER EVP_hw_c = {NID_des_ecb, 1, 8,    0,    8,    hw_init_key, hw_cipher_enc,
                                    NULL,        1, NULL, NULL, NULL, NULL};
const EVP_CIPHER* EVP_hw_cipher(void) {
    return (&EVP_hw_c);
}
/* 选择对称计算函数 */
static int cipher_nids[] = {NID_des_ecb, NID_des_ede3_cbc, 0};
static int hw_ciphers(ENGINE* e, const EVP_CIPHER** cipher, const int** nids, int nid) {
    if (cipher == NULL) {
        *nids = cipher_nids;
        return (sizeof(cipher_nids) - 1) / sizeof(cipher_nids[0]);
    }
    switch (nid) {
    case NID_des_ecb:
        *cipher = EVP_hw_ciphe() r;
        break;
        //其他对称函数
    }
    return 1;
}
static int init(EVP_MD_CTX* ctx) {
    printf("call md init\n");
    return 1;
}
static int update(EVP_MD_CTX* ctx, const void* data, size_t count) {
    printf("call md update\n");
    return 1;
}
static int final(EVP_MD_CTX* ctx, unsigned char* md) {
    int i;
    printf("call md final\n");
    for (i = 0; i < 20; i++)
        memset(md++, i, 1);
    return 1;
}
int mySign(int type, const unsigned char* m, unsigned int m_length, unsigned char* sigret,
           unsigned int* siglen, void* key) {
    RSA* k;
    int keyid;
    k = (RSA*)key;
    /* 获取硬件中的私钥ID，进行计算 */
    keyid = ENGINE_get_ex_data(k->engine, 0);
    printf("call mySign\n");
    printf("use key id is %d\n", keyid);
    return 1;
}
int myVerify(int type, const unsigned char* m, unsigned int m_length, const unsigned char* sigbuf,
             unsigned int siglen, void* key) {
    printf("call myVerify\n");
    return 1;
}
static int digest_nids[] = {NID_sha1, NID_md5, 0};
/* 实现的sha1摘要算法 */
static const EVP_MD hw_newmd = {NID_sha1, NID_sha1WithRSAEncryption, SHA_DIGEST_LENGTH, 0, init,
                                update, final, NULL, NULL, mySign, /* sign */
                                myVerify,                          /* verify */
                                // sizeof(EVP_MD *)+sizeof(SHA_CTX),
                                6};
static EVP_MD* EVP_hw_md() {
    return (&hw_newmd);
}
/* 选择摘要算法的函数 */
static int hw_md(ENGINE* e, const EVP_MD** digest, const int** nids, int nid) {
    if (digest == NULL) {
        *nids = digest_nids;
        return (sizeof(digest_nids) - 1) / sizeof(digest_nids[0]);
    }
    switch (nid) {
    case NID_sha1:
        *digest = EVP_hw_md();
        break;
        //其他摘要函数
    }
    return 1;
}
static int bind_helper(ENGINE* e) {
    int ret;
    ret = ENGINE_set_id(e, engine_hw_id);
    if (ret != 1) {
        printf("ENGINE_set_id failed\n");
        return 0;
    }
    ret = ENGINE_set_name(e, engine_hw_name);
    if (ret != 1) {
        printf("ENGINE_set_name failed\n");
        return 0;
    }
    ret = ENGINE_set_RSA(e, &hw_rsa);
    if (ret != 1) {
        printf("ENGINE_set_RSA failed\n");
        return 0;
    }
    ret = ENGINE_set_RAND(e, &hw_rand);
    if (ret != 1) {
        printf("ENGINE_set_RAND failed\n");
        return 0;
    }
    ret = ENGINE_set_destroy_function(e, hw_destroy);
    if (ret != 1) {
        printf("ENGINE_set_destroy_function failed\n");
        return 0;
    }
    ret = ENGINE_set_init_function(e, hw_init);
    if (ret != 1) {
        printf("ENGINE_set_init_function failed\n");
        return 0;
    }
    ret = ENGINE_set_finish_function(e, hw_finish);
    if (ret != 1) {
        printf("ENGINE_set_finish_function failed\n");
        return 0;
    }
    ret = ENGINE_set_ctrl_function(e, hw_ctrl);
    if (ret != 1) {
        printf("ENGINE_set_ctrl_function failed\n");
        return 0;
    }
    ret = ENGINE_set_load_privkey_function(e, hw_load_privkey);
    if (ret != 1) {
        printf("ENGINE_set_load_privkey_function failed\n");
        return 0;
    }
    ret = ENGINE_set_load_pubkey_function(e, hw_load_pubkey);
    if (ret != 1) {
        printf("ENGINE_set_load_pubkey_function failed\n");
        return 0;
    }
    ret = ENGINE_set_cmd_defns(e, hw_cmd_defns);
    if (ret != 1) {
        printf("ENGINE_set_cmd_defns failed\n");
        return 0;
    }
    ret = ENGINE_set_ciphers(e, hw_ciphers);
    if (ret != 1) {
        printf("ENGINE_set_ciphers failed\n");
        return 0;
    }
    ret = ENGINE_set_digests(e, hw_md);
    if (ret != 1) {
        printf("ENGINE_set_digests failed\n");
        return 0;
    }
    return 1;
}
static ENGINE* engine_hwcipher(void) {
    ENGINE* ret = ENGINE_new();
    if (!ret)
        return NULL;
    if (!bind_helper(ret)) {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}
void ENGINE_load_hwcipher() {
    ENGINE* e_hw = engine_hwcipher();
    if (!e_hw)
        return;
    ENGINE_add(e_hw);
    ENGINE_free(e_hw);
    ERR_clear_error();
}

/*测试主函数*/
#define HW_set_private_keyID(a) func(e, a, 0, (void*)1, NULL)
#include <openssl/engine.h>
#include <openssl/evp.h>
int main() {
    ENGINE* e;
    RSA_METHOD* meth;
    int ret, num = 20, i;
    char buf[20], *name;
    EVP_CIPHER* cipher;
    EVP_MD* md;
    EVP_MD_CTX mctx, md_ctx;
    EVP_CIPHER_CTX ciph_ctx, dciph_ctx;
    unsigned char key[8], iv[8];
    unsigned char in[50], out[100], dd[60];
    int inl, outl, total, dtotal;
    RSA* rkey;
    RSA_METHOD* rsa_m;
    EVP_PKEY *ek, *pkey;
    ENGINE_CTRL_FUNC_PTR func;
    OpenSSL_add_all_algorithms();
    ENGINE_load_hwcipher();
    e = ENGINE_by_id("ID_hw");
    name = (char*)ENGINE_get_name(e);
    printf("engine name :%s \n", name);
    /* 随机数生成 */
    ret = RAND_set_rand_engine(e);
    if (ret != 1) {
        printf("RAND_set_rand_engine err\n");
        return -1;
    }
    ret = ENGINE_set_default_RAND(e);
    if (ret != 1) {
        printf("ENGINE_set_default_RAND err\n");
        return -1;
    }
    ret = RAND_bytes((unsigned char*)buf, num);
    /* 对称加密 */
    for (i = 0; i < 8; i++)
        memset(&key[i], i, 1);
    EVP_CIPHER_CTX_init(&ciph_ctx);
    /* 采用Engine对称算法 */
    cipher = EVP_des_ecb();
    ret = EVP_EncryptInit_ex(&ciph_ctx, cipher, e, key, iv);
    if (ret != 1) {
        printf("EVP_EncryptInit_ex err\n");
        return -1;
    }
    strcpy((char*)in, "zcpsssssssssssss");
    inl = strlen((const char*)in);
    total = 0;
    ret = EVP_EncryptUpdate(&ciph_ctx, out, &outl, in, inl);
    if (ret != 1) {
        printf("EVP_EncryptUpdate err\n");
        return -1;
    }
    total += outl;
    ret = EVP_EncryptFinal(&ciph_ctx, out + total, &outl);
    if (ret != 1) {
        printf("EVP_EncryptFinal err\n");
        return -1;
    }
    total += outl;
    /* 解密 */
    dtotal = 0;
    EVP_CIPHER_CTX_init(&dciph_ctx);
    ret = EVP_DecryptInit_ex(&dciph_ctx, cipher, e, key, iv);
    if (ret != 1) {
        printf("EVP_DecryptInit_ex err\n");
        return -1;
    }
    ret = EVP_DecryptUpdate(&dciph_ctx, dd, &outl, out, total);
    if (ret != 1) {
        printf("EVP_DecryptUpdate err\n");
        return -1;
    }
    dtotal += outl;
    ret = EVP_DecryptFinal(&dciph_ctx, dd + dtotal, &outl);
    if (ret != 1) {
        printf("EVP_DecryptFinal err\n");
        return -1;
    }
    dtotal += outl;
    /* Engine摘要 */
    EVP_MD_CTX_init(&mctx);
    md = EVP_sha1();
    ret = EVP_DigestInit_ex(&mctx, md, e);
    if (ret != 1) {
        printf("EVP_DigestInit_ex err.\n");
        return -1;
    }
    ret = EVP_DigestUpdate(&mctx, in, inl);
    if (ret != 1) {
        printf("EVP_DigestInit_ex err.\n");
        return -1;
    }
    ret = EVP_DigestFinal(&mctx, out, (unsigned int*)&outl);
    if (ret != 1) {
        printf("EVP_DigestInit_ex err.\n");
        return -1;
    }
    func = ENGINE_get_ctrl_function(e);
    /* 设置计算私钥ID */
    HW_set_private_keyID(1);
    rkey = RSA_new_method(e);
    pkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pkey, rkey);
    EVP_MD_CTX_init(&md_ctx);
    ret = EVP_SignInit_ex(&md_ctx, EVP_sha1(), e);
    if (ret != 1) {
        printf("EVP_SignInit_ex err\n");
        return -1;
    }
    ret = EVP_SignUpdate(&md_ctx, in, inl);
    if (ret != 1) {
        printf("EVP_SignUpdate err\n");
        return -1;
    }
    ret = EVP_SignFinal(&md_ctx, out, (unsigned int*)&outl, pkey);
    if (ret != 1) {
        printf("EVP_SignFinal err\n");
        return -1;
    }
    /* 私钥加密 */
    RSA_private_encrypt(inl, in, out, rkey, 1);
    /* 公钥解密 */
    /* 公钥加密 */
    /* 私钥解密 */
    printf("all test ok.\n");
    ENGINE_free(e);
    ENGINE_finish(e);
    return 0;
}
```

