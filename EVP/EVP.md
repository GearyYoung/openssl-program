# 第二十一章 EVP

## 21.1 EVP  简介

​	Openssl EVP(high-level cryptographic functions[1])提供了丰富的密码学中的各种函数。Openssl中实现了各种对称算法、摘要算法以及签名/验签算法。EVP函数将这些具体的算法进行了封装。

​	EVP主要封装了如下功能函数：

1. 实现了base64编解码BIO；
2. 实现了加解密BIO；
3. 实现了摘要BIO；
4. 实现了reliable BIO；
5. 封装了摘要算法；
6. 封装了对称加解密算法；
7. 封装了非对称密钥的加密(公钥)、解密(私钥)、签名与验证以及辅助函数；
8. 基于口令的加密(PBE)；
9. 对称密钥处理；
10. 数字信封：数字信封用对方的公钥加密对称密钥，数据则用此对称密钥加密。发送给对方时，同时发送对称密钥密文和数据密文。接收方首先用自己的私钥解密密钥密文，得到对称密钥，然后用它解密数据。
11. 其他辅助函数。

## 21.2  数据结构

​	EVP数据结构定义在crypto/evp.h中，如下所示：

### 21.2.1 EVP_PKEY

```cpp
struct evp_pkey_st {
    int references;
    union {
        char* ptr;
#ifndef OPENSSL_NO_RSA
        struct rsa_st* rsa; /* RSA */
#endif
#ifndef OPENSSL_NO_DSA
        struct dsa_st* dsa; /* DSA */
#endif
#ifndef OPENSSL_NO_DH
        struct dh_st* dh; /* DH */
#endif
#ifndef OPENSSL_NO_EC
        struct ec_key_st* ec; /* ECC */
#endif
    } pkey;
    STACK_OF(X509_ATTRIBUTE) * attributes; /* [ 0 ] */
};
```

​	该结构用来存放非对称密钥信息，可以是RSA、DSA、DH或ECC密钥。其中，ptr用来存放密钥结构地址，attributes堆栈用来存放密钥属性。

### 21.2.2 EVP_MD

```cpp
struct env_md_st {
    int type;
    int pkey_type;
    int md_size;
    unsigned long flags;
    int (*init)(EVP_MD_CTX* ctx);
    int (*update)(EVP_MD_CTX* ctx, const void* data, size_t count);
    int (* final)(EVP_MD_CTX* ctx, unsigned char* md);
    int (*copy)(EVP_MD_CTX* to, const EVP_MD_CTX* from);
    int (*cleanup)(EVP_MD_CTX* ctx);
    int (*sign)(int type, const unsigned char* m, unsigned int m_length, unsigned char* sigret,
                unsigned int* siglen, void* key);
    int (*verify)(int type, const unsigned char* m, unsigned int m_length,
                  const unsigned char* sigbuf, unsigned int siglen, void* key);
    int required_pkey_type[5];
    int block_size;
    int ctx_size; /* how big does the ctx->md_data need to be */
};
```

​	该结构用来存放摘要算法信息、非对称算法类型以及各种计算函数。主要各项意义如下：

* type：摘要类型，一般是摘要算法NID；
* pkey_type：公钥类型，一般是签名算法NID；
* md_size：摘要值大小，为字节数；
* flags：用于设置标记；
* init：摘要算法初始化函数；
* update：多次摘要函数；
* final：摘要完结函数；
* copy：摘要上下文结构复制函数；
* cleanup：清除摘要上下文函数；
* sign：签名函数，其中key为非对称密钥结构地址；
* verify：摘要函数，其中key为非对称密钥结构地址。

  ​openssl对于各种摘要算法实现了上述结构，各个源码位于cypto/evp目录下，文件名以m_开头。Openssl通过这些结构来封装了各个摘要相关的运算。

### 21.2.3 EVP_CIPHER

```cpp
struct evp_cipher_st {
    int nid;
    int block_size;
    int key_len;
    int iv_len;
    unsigned long flags;
    int (*init)(EVP_CIPHER_CTX* ctx, const unsigned char* key, const unsigned char* iv, int enc);
    int (*do_cipher)(EVP_CIPHER_CTX* ctx, unsigned char* out, const unsigned char* in,
                     unsigned int inl);
    int (*cleanup)(EVP_CIPHER_CTX*); /* cleanup ctx */
    int ctx_size;
    int (*set_asn1_parameters)(EVP_CIPHER_CTX*, ASN1_TYPE*);
    int (*get_asn1_parameters)(EVP_CIPHER_CTX*, ASN1_TYPE*);
    int (*ctrl)(EVP_CIPHER_CTX*, int type, int arg, void* ptr);
    void* app_data;
};
```

​	该结构用来存放对称加密相关的信息以及算法。主要各项意义如下：

* nid：对称算法nid；
* block_size：对称算法每次加解密的字节数；
* key_len：对称算法的密钥长度字节数；
* iv_len：对称算法的填充长度；
* flags：用于标记；
* init：加密初始化函数，用来初始化ctx，key为对称密钥值，iv为初始化向量，enc用于指明是要加密还是解密，这些信息存放在ctx中；
* do_cipher：对称运算函数，用于加密或解密；
* cleanup：清除上下文函数；
* set_asn1_parameters：设置上下文参数函数；
* get_asn1_parameters：获取上下文参数函数；
* ctrl：控制函数；
* app_data：用于存放应用数据。

  ​openssl对于各种对称算法实现了上述结构，各个源码位于cypto/evp目录下，文件名以e_开头。Openssl通过这些结构来封装了对称算法相关的运算。

### 21.2.4 EVP_CIPHER_CTX

```cpp
struct evp_cipher_ctx_st {
    const EVP_CIPHER* cipher;
    ENGINE* engine;
    int encrypt;
    int buf_len;
    unsigned char oiv[EVP_MAX_IV_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];
    unsigned char buf[EVP_MAX_BLOCK_LENGTH];
    /* 其他 */
    unsigned char final[EVP_MAX_BLOCK_LENGTH];
};
```

​	对称算法上下文结构，此结构主要用来维护加解密状态，存放中间以及最后结果。因为加密或解密时，当数据很多时，可能会用到Update函数，并且每次加密或解密的输入数据长度任意的，并不一定是对称算法block_size的整数倍，所以需要用该结构来存放中间未加密的数据。主要项意义如下：

* cipher：指明对称算法；
* engine：硬件引擎；
* encrypt：是加密还是解密；非0为加密，0为解密；
* buf 和buf_len：指明还有多少数据未进行运算；
* oiv：原始初始化向量；
* iv：当前的初始化向量；
* final：存放最终结果，一般与Final函数对应。

## 21.3  源码结构

​	evp源码位于crypto/evp目录，可以分为如下几类：

1. 全局函数

   主要包括c_allc.c、c_alld.c、c_all.c以及names.c。他们加载openssl支持的所有的对称算法和摘要算法，放入到哈希表中。实现了OpenSSL_add_all_digests、OpenSSL_add_all_ciphers以及OpenSSL_add_all_algorithms(调用了前两个函数)函数。在进行计算时，用户也可以单独加载摘要函数（EVP_add_digest）和对称计算函数（EVP_add_cipher）。

2. BIO扩充

   包括bio_b64.c、bio_enc.c、bio_md.c和bio_ok.c，各自实现了BIO_METHOD方法，分别用于base64编解码、对称加解密以及摘要。

3. 摘要算法EVP封装

   由digest.c实现，实现过程中调用了对应摘要算法的回调函数。各个摘要算法提供了自己的EVP_MD静态结构，对应源码为m_xxx.c。

4. 对称算法EVP封装

   由evp_enc.c实现，实现过程调用了具体对称算法函数，实现了Update操作。各种对称算法都提供了一个EVP_CIPHER静态结构，对应源码为e_xxx.c。需要注意的是，e_xxx.c中不提供完整的加解密运算，它只提供基本的对于一个block_size数据的计算，完整的计算由evp_enc.c来实现。当用户想添加一个自己的对称算法时，可以参考e_xxx.c的实现方式。一般用户至少需要实现如下功能：

* 构造一个新的静态的EVP_CIPHER结构；
* 实现EVP_CIPHER结构中的init函数，该函数用于设置iv，设置加解密标记、以及根据外送密钥生成自己的内部密钥；
* 实现do_cipher函数，该函数仅对block_size字节的数据进行对称运算；


* 实现cleanup函数，该函数主要用于清除内存中的密钥信息。

5. 非对称算法EVP封装

   主要是以p_开头的文件。其中，p_enc.c封装了公钥加密；p_dec.c封装了私钥解密；p_lib.c实现一些辅助函数；p_sign.c封装了签名函数；p_verify.c封装了验签函数；p_seal.c封装了数字信封；p_open.c封装了解数字信封。

6. 基于口令的加密

   包括p5_crpt2.c、p5_crpt.c和evp_pbe.c。

## 21.4  摘要函数

​	典型的摘要函数主要有：

1. EVP_md5

       返回md5的EVP_MD。

2. EVP_sha1

       返回sha1的EVP_MD。

3. EVP_sha256

       返回sha256的EVP_MD。

4. EVP_DigestInit

     摘要初使化函数，需要有EVP_MD作为输入参数。

5. EVP_DigestUpdate和EVP_DigestInit_ex

       摘要Update函数，用于进行多次摘要。

6. EVP_DigestFinal和EVP_DigestFinal_ex

       摘要Final函数，用户得到最终结果。

7. EVP_Digest

       对一个数据进行摘要，它依次调用了上述三个函数。

## 21.5  对称加解密函数

​	典型的加解密函数主要有：

1. EVP_CIPHER_CTX_init

   初始化对称计算上下文。

2. EVP_CIPHER_CTX_cleanup

   清除对称算法上下文数据，它调用用户提供的销毁函数销清除存中的内部密钥以及其他数据。


3. EVP_des_ede3_ecb

   返回一个EVP_CIPHER；

4. EVP_EncryptInit和EVP_EncryptInit_ex

   加密初始化函数，本函数调用具体算法的init回调函数，将外送密钥key转换为内部密钥形式，将初始化向量iv拷贝到ctx结构中。

5. EVP_EncryptUpdate

   加密函数，用于多次计算，它调用了具体算法的do_cipher回调函数。

6. EVP_EncryptFinal和EVP_EncryptFinal_ex

   获取加密结果，函数可能涉及填充，它调用了具体算法的do_cipher回调函数。

7. EVP_DecryptInit和EVP_DecryptInit_ex

   解密初始化函数。

8. EVP_DecryptUpdate

   解密函数，用于多次计算，它调用了具体算法的do_cipher回调函数。

9. EVP_DecryptFinal和EVP_DecryptFinal_ex

   获取解密结果，函数可能涉及去填充，它调用了具体算法的do_cipher回调函数。

10. EVP_BytesToKey

   计算密钥函数，它根据算法类型、摘要算法、salt以及输入数据计算出一个对称密钥和初始化向量iv。

11. PKCS5_PBE_keyivgen和PKCS5_v2_PBE_keyivgen

   实现了PKCS5基于口令生成密钥和初始化向量的算法。

12. PKCS5_PBE_add

   加载所有openssl实现的基于口令生成密钥的算法。

13. EVP_PBE_alg_add

   添加一个PBE算法。

## 21.6  非对称函数

​	典型的非对称函数有：

1. EVP_PKEY_encrypt

   公钥加密。

2. EVP_PKEY_decrypt

   私钥解密。

3. EVP_PKEY_assign

   设置EVP_PKEY中具体的密钥结构，使它代表该密钥。

4. EVP_PKEY_assign_RSA/ EVP_PKEY_set1_RSA

   设置EVP_PKEY中的RSA密钥结构，使它代表该RSA密钥。

5. EVP_PKEY_get1_RSA

   获取EVP_PKEY的RSA密钥结构。

6. EVP_SignFinal

   签名操作，输入参数必须有私钥(EVP_PKEY)。

7. EVP_VerifyFinal

   验证签名，输入参数必须有公钥(EVP_PKEY)。

8. `int EVP_OpenInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,const unsigned char *ek, int ekl, const unsigned char *iv,EVP_PKEY *priv)`

   解数字信封初始化操作，type为对称加密算法，ek为密钥密文，ekl为密钥密文长度，iv为填充值，priv为用户私钥。

9. EVP_OpenUpdate

        做解密运算。

10.  EVP_OpenFinal

    做解密运算，解开数字信封。

11.  `int EVP_SealInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, unsigned char **ek,int *ekl, unsigned char *iv, EVP_PKEY **pubk, int npubk)`

    type为对称算法，ek数组用来存放多个公钥对密钥加密的结果，ekl用于存放ek数组中每个密钥密文的长度，iv为填充值，pubk数组用来存放多个公钥，npubk为公钥个数，本函数用多个公钥分别加密密钥，并做加密初始化。

12.  EVP_SealUpdate

    做加密运算。

13.  EVP_SealFinal

    做加密运算，制作数字信封。

## 21.7  BASE64编解码函数

1. EVP_EncodeInit

   BASE64编码初始化。

2. EVP_EncodeUpdate

   BASE64编码，可多次调用。

3. EVP_EncodeFinal

   BASE64编码，并获取最终结果。

4. EVP_DecodeInit

   BASE64解码初始化。

5. EVP_DecodeUpdate

   输入数据长度不能大于80字节。BASE64解码可多次调用，注意，本函数的输入数据不能太长。

6. EVP_DecodeFinal

   BASE64解码，并获取最终结果。

7. EVP_EncodeBlock

   BASE64编码函数，本函数可单独调用。

8. EVP_DecodeBlock

   BASE64解码，本函数可单独调用，对输入数据长度无要求。

## 21.8  其他函数

1. EVP_add_cipher

   将对称算法加入到全局变量，以供调用。

2. EVP_add_digest

   将摘要算法加入到全局变量中，以供调用。

3. EVP_CIPHER_CTX_ctrl

   对称算法控制函数，它调用了用户实现的ctrl回调函数。

4. EVP_CIPHER_CTX_set_key_length

   当对称算法密钥长度为可变长时，设置对称算法的密钥长度。

5. EVP_CIPHER_CTX_set_padding

   设置对称算法的填充，对称算法有时候会涉及填充。加密分组长度大于一时，用户输入数据不是加密分组的整数倍时，会涉及到填充。填充在最后一个分组来完成，openssl分组填充时，如果有n个填充，则将最后一个分组用n来填满。

6. EVP_CIPHER_get_asn1_iv

   获取原始iv，存放在ASN1_TYPE结构中。

7. EVP_CIPHER_param_to_asn1

   设置对称算法参数，参数存放在ASN1_TYPE类型中，它调用用户实现的回调函数set_asn1_parameters来实现。

8. EVP_CIPHER_type

   获取对称算法的类型。

9. EVP_CipherInit/EVP_CipherInit_ex

   对称算法计算(加/解密)初始化函数，_ex函数多了硬件enginge参数，EVP_EncryptInit和EVP_DecryptInit函数也调用本函数。

10. EVP_CipherUpdate

   对称计算（加/解密）函数，它调用了EVP_EncryptUpdate和EVP_DecryptUpdate函数。

11. EVP_CipherFinal/EVP_CipherFinal_ex

   对称计算(加/解)函数，调用了EVP_EncryptFinal（_ex）和EVP_DecryptFinal(_ex）；本函数主要用来处理最后加密分组，可能会有对称计算。

12. EVP_cleanup

   清除加载的各种算法，包括对称算法、摘要算法以及PBE算法，并清除这些算法相关的哈希表的内容。

13. EVP_get_cipherbyname

   根据字串名字来获取一种对称算法(EVP_CIPHER)，本函数查询对称算法哈希表。

14. EVP_get_digestbyname

   根据字串获取摘要算法(EVP_MD)，本函数查询摘要算法哈希表。

15. EVP_get_pw_prompt

   获取口令提示信息字符串.

16. `int EVP_PBE_CipherInit(ASN1_OBJECT *pbe_obj, const char *pass, int passlen,ASN1_TYPE *param, EVP_CIPHER_CTX *ctx, int en_de)`

   PBE初始化函数。本函数用口令生成对称算法的密钥和初始化向量，并作加/解密初始化操作。本函数再加上后续的EVP_CipherUpdate以及EVP_CipherFinal_ex构成一个完整的加密过程（可参考crypto/p12_decr.c的PKCS12_pbe_crypt函数）.

17. EVP_PBE_cleanup

   删除所有的PBE信息，释放全局堆栈中的信息.

18. `EVP_PKEY *EVP_PKCS82PKEY(PKCS8_PRIV_KEY_INFO *p8)`

   将PKCS8_PRIV_KEY_INFO(x509.h中定义)中保存的私钥转换为EVP_PKEY结构。

19. EVP_PKEY2PKCS8/EVP_PKEY2PKCS8_broken

   将EVP_PKEY结构中的私钥转换为PKCS8_PRIV_KEY_INFO数据结构存储。

20. EVP_PKEY_bits

   非对称密钥大小，为比特数。

21. EVP_PKEY_cmp_parameters

   比较非对称密钥的密钥参数，用于DSA和ECC密钥。

22. EVP_PKEY_copy_parameters

   拷贝非对称密钥的密钥参数，用于DSA和ECC密钥。

23. EVP_PKEY_free

   释放非对称密钥数据结构。

24. EVP_PKEY_get1_DH/EVP_PKEY_set1_DH

   获取/设置EVP_PKEY中的DH密钥。

25. EVP_PKEY_get1_DSA/EVP_PKEY_set1_DSA

   获取/设置EVP_PKEY中的DSA密钥。

26. EVP_PKEY_get1_RSA/EVP_PKEY_set1_RSA

   获取/设置EVP_PKEY中结构中的RSA结构密钥。

27. EVP_PKEY_missing_parameters

   检查非对称密钥参数是否齐全，用于DSA和ECC密钥。

28. EVP_PKEY_new

   生成一个EVP_PKEY结构。

29. EVP_PKEY_size

   获取非对称密钥的字节大小。

30. EVP_PKEY_type

   获取EVP_PKEY中表示的非对称密钥的类型。

31. `int   EVP_read_pw_string(char *buf,int length,const char *prompt,int verify)`

   获取用户输入的口令；buf用来存放用户输入的口令，length为buf长度，prompt为提示给用户的信息，如果为空，它采用内置的提示信息，verify为0时，不要求验证用户输入的口令，否则回要求用户输入两遍。返回0表示成功。

32. EVP_set_pw_prompt

   设置内置的提示信息，用于需要用户输入口令的场合。

## 21.9  对称加密过程

​	对称加密过程如下：   

1. EVP_EncryptInit：

   设置buf_len为0，表明临时缓冲区buf没有数据。

2. EVP_EncryptUpdate：

   ctx结构中的buf缓冲区用于存放上次EVP_EncryptUpdate遗留下来的未加密的数据，buf_len指明其长度。如果buf_len为0，加密的时候先加密输入数据的整数倍，将余下的数据拷贝到buf缓冲区。如果buf_len不为0，先加密buf里面的数据和输入数据的一部分（凑足一个分组的长度），然后用上面的方法加密，输出结果是加过密的数据。

3. EVP_ EncryptFinal

   加密ctx的buf中余下的数据，如果长度不够一个分组（分组长度不为1），则填充，然后再加密，输出结果。

   ​总之，加密大块数据（比如一个大的文件，多出调用EVP_EncryptUpdate）的结果等效于将所有的数据一次性读入内存进行加密的结果。加密和解密时每次计算的数据块的大小不影响其运算结果。



## 21.10  编程示例

​	**示例1**

```cpp
#include <openssl/evp.h>
#include <string.h>
int main() {
    int ret, which = 1;
    EVP_CIPHER_CTX ctx;
    const EVP_CIPHER* cipher;
    unsigned char key[24], iv[8], in[100], out[108], de[100];
    int i, len, inl, outl, total = 0;
    for (i = 0; i < 24; i++) {
        memset(&key[i], i, 1);
    }
    for (i = 0; i < 8; i++) {
        memset(&iv[i], i, 1);
    }
    for (i = 0; i < 100; i++) {
        memset(&in[i], i, 1);
    }
    EVP_CIPHER_CTX_init(&ctx);
    printf("please select :\n");
    printf("1: EVP_des_ede3_ofb\n");
    printf("2: EVP_des_ede3_cbc\n");
    scanf("%d", &which);
    if (which == 1)
        cipher = EVP_des_ede3_ofb();
    else
        cipher = EVP_des_ede3_cbc();
    ret = EVP_EncryptInit_ex(&ctx, cipher, NULL, key, iv);
    if (ret != 1) {
        printf("EVP_EncryptInit_ex err1!\n");
        return -1;
    }
    inl = 50;
    len = 0;
    EVP_EncryptUpdate(&ctx, out + len, &outl, in, inl);
    len += outl;
    EVP_EncryptUpdate(&ctx, out + len, &outl, in + 50, inl);
    len += outl;
    EVP_EncryptFinal_ex(&ctx, out + len, &outl);
    len += outl;
    printf("加密结果长度：%d\n", len);
    /* 解密 */
    EVP_CIPHER_CTX_cleanup(&ctx);
    EVP_CIPHER_CTX_init(&ctx);
    ret = EVP_DecryptInit_ex(&ctx, cipher, NULL, key, iv);
    if (ret != 1) {
        printf("EVP_DecryptInit_ex err1!\n");
        return -1;
    }
    total = 0;
    EVP_DecryptUpdate(&ctx, de + total, &outl, out, 44);
    total += outl;
    EVP_DecryptUpdate(&ctx, de + total, &outl, out + 44, len - 44);
    total += outl;
    ret = EVP_DecryptFinal_ex(&ctx, de + total, &outl);
    total += outl;
    if (ret != 1) {
        EVP_CIPHER_CTX_cleanup(&ctx);
        printf("EVP_DecryptFinal_ex err\n");
        return -1;
    }

    if ((total != 100) || (memcmp(de, in, 100))) {
        printf("err!\n");
        return -1;
    }
    EVP_CIPHER_CTX_cleanup(&ctx);
    printf("test ok!\n");
    return 0;
}
```

​	输出结果如下：

```verilog
please select :
       1: EVP_des_ede3_ofb
       2: EVP_des_ede3_cbc
       1
加密结果长度：100
       test ok!
       please select :
       1: EVP_des_ede3_ofb
       2: EVP_des_ede3_cbc
       2
加密结果长度：104
       test ok!
```

​	**示例2**

```cpp
#include <openssl/evp.h>
#include <string.h>
int main() {
    int cnid, ret, i, msize, mtype;
    int mpktype, cbsize, mnid, mbsize;
    const EVP_CIPHER* type;
    const EVP_MD* md;
    int datal, count, keyl, ivl;
    unsigned char salt[20], data[100], *key, *iv;
    const char *cname, *mname;
    type = EVP_des_ecb();
    cnid = EVP_CIPHER_nid(type);
    cname = EVP_CIPHER_name(type);
    cbsize = EVP_CIPHER_block_size(type);
    printf("encrypto nid : %d\n", cnid);
    printf("encrypto name: %s\n", cname);
    printf("encrypto bock size : %d\n", cbsize);
    md = EVP_md5();
    mtype = EVP_MD_type(md);
    mnid = EVP_MD_nid(md);
    mname = EVP_MD_name(md);
    mpktype = EVP_MD_pkey_type(md);
    msize = EVP_MD_size(md);
    mbsize = EVP_MD_block_size(md);
    printf("md info : \n");
    printf("md type  : %d\n", mtype);
    printf("md nid  : %d\n", mnid);
    printf("md name : %s\n", mname);
    printf("md pkey type : %d\n", mpktype);
    printf("md size : %d\n", msize);
    printf("md block size : %d\n", mbsize);
    keyl = EVP_CIPHER_key_length(type);
    key = (unsigned char*)malloc(keyl);
    ivl = EVP_CIPHER_iv_length(type);
    iv = (unsigned char*)malloc(ivl);
    for (i = 0; i < 100; i++)
        memset(&data[i], i, 1);
    for (i = 0; i < 20; i++)
        memset(&salt[i], i, 1);
    datal = 100;
    count = 2;
    ret = EVP_BytesToKey(type, md, salt, data, datal, count, key, iv);
    printf("generate key value: \n");
    for (i = 0; i < keyl; i++)
        printf("%x ", *(key + i));
    printf("\n");
    printf("generate iv value: \n");
    for (i = 0; i < ivl; i++)
        printf("%x ", *(iv + i));
    printf("\n");
    return 0;
}
```

​	 EVP_BytesToKey函数通过salt以及data数据来生成所需要的key和iv。

输出：

```log
encrypto nid : 29
encrypto name: DES-ECB
encrypto bock size : 8
md info :
md type  : 4
md nid  : 4
md name : MD5
md pkey type : 8
md size : 16
md block size : 64
generate key value:
	54 0 b1 24 18 42 8d dd
generate iv value:
	ba 7d c3 97 a0 c9 e0 70
```

​	**示例3**

```cpp
#include <openssl/evp.h>
#include <openssl/rsa.h>
int main() {
    int ret, inlen, outlen = 0;
    unsigned long e = RSA_3;
    char data[100], out[500];
    EVP_MD_CTX md_ctx, md_ctx2;
    EVP_PKEY* pkey;
    RSA* rkey;
    BIGNUM* bne;
    /* 待签名数据*/
    strcpy(data, "openssl 编程作者：赵春平");
    inlen = strlen(data);
    /* 生成RSA密钥*/
    bne = BN_new();
    ret = BN_set_word(bne, e);
    rkey = RSA_new();
    ret = RSA_generate_key_ex(rkey, 1024, bne, NULL);
    if (ret != 1)
        goto err;
    pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rkey);
    /* 初始化*/
    EVP_MD_CTX_init(&md_ctx);
    ret = EVP_SignInit_ex(&md_ctx, EVP_md5(), NULL);
    if (ret != 1)
        goto err;
    ret = EVP_SignUpdate(&md_ctx, data, inlen);
    if (ret != 1)
        goto err;
    ret = EVP_SignFinal(&md_ctx, out, &outlen, pkey);
    /* 验证签名*/
    EVP_MD_CTX_init(&md_ctx2);
    ret = EVP_VerifyInit_ex(&md_ctx2, EVP_md5(), NULL);
    if (ret != 1)
        goto err;
    ret = EVP_VerifyUpdate(&md_ctx2, data, inlen);
    if (ret != 1)
        goto err;
    ret = EVP_VerifyFinal(&md_ctx2, out, outlen, pkey);
    if (ret == 1)
        printf("验证成功\n");
    else
        printf("验证错误\n");
err:
    RSA_free(rkey);
    BN_free(bne);
    return 0;
}
```



​	**示例4**

```cpp
#include <openssl/evp.h>
#include <openssl/rsa.h>
int main() {
    int ret, ekl[2], npubk, inl, outl, total = 0, total2 = 0;
    unsigned long e = RSA_3;
    char *ek[2], iv[8], in[100], out[500], de[500];
    EVP_CIPHER_CTX ctx, ctx2;
    EVP_CIPHER* type;
    EVP_PKEY* pubkey[2];
    RSA* rkey;
    BIGNUM* bne;
    /* 生成RSA密钥*/
    bne = BN_new();
    ret = BN_set_word(bne, e);
    rkey = RSA_new();
    ret = RSA_generate_key_ex(rkey, 1024, bne, NULL);
    pubkey[0] = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pubkey[0], rkey);
    type = EVP_des_cbc();
    npubk = 1;
    EVP_CIPHER_CTX_init(&ctx);
    ek[0] = malloc(500);
    ek[1] = malloc(500);
    ret = EVP_SealInit(&ctx, type, ek, ekl, iv, pubkey, 1); /* 只有一个公钥*/
    if (ret != 1)
        goto err;
    strcpy(in, "openssl 编程");
    inl = strlen(in);
    ret = EVP_SealUpdate(&ctx, out, &outl, in, inl);
    if (ret != 1)
        goto err;
    total += outl;
    ret = EVP_SealFinal(&ctx, out + outl, &outl);
    if (ret != 1)
        goto err;
    total += outl;
    memset(de, 0, 500);
    EVP_CIPHER_CTX_init(&ctx2);
    ret = EVP_OpenInit(&ctx2, EVP_des_cbc(), ek[0], ekl[0], iv, pubkey[0]);
    if (ret != 1)
        goto err;
    ret = EVP_OpenUpdate(&ctx2, de, &outl, out, total);
    total2 += outl;
    ret = EVP_OpenFinal(&ctx2, de + outl, &outl);
    total2 += outl;
    de[total2] = 0;
    printf("%s\n", de);
err:
    free(ek[0]);
    free(ek[1]);
    EVP_PKEY_free(pubkey[0]);
    BN_free(bne);
    getchar();
    return 0;
}
```

