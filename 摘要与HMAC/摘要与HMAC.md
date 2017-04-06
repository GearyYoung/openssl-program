# 第十五章 摘要与HMAC

## 15.1  概述

​	摘要函数用于将任意数据通过计算获取唯一对应值，而这个值的长度比较短。它是一种多对一的关系。理论上，这个短的值就对应于原来的数据。这个过程是不可逆的，即不能通过摘要值来计算原始数据。摘要在信息安全中有非常重要的作用。很多网络应用都通过摘要计算来存放口令。摘要是安全协议中不可或却的要素，特别是身份认证与签名。用户需要对数据进行签名时，不可能对大的数据进行运算，这样会严重影响性能。如果只对摘要结果进行计算，则会提供运算速度。常用摘要算法有：sha、sha1、sha256以及md5等。其他还有md4、md2、mdc2以及ripemd160等。

## 15.2  openssl摘要实现

​	openssl摘要实现的源码位于crypto目录下的各个子目录下，如下所示：

> crypto/ripemd：ripemd摘要实现(包括汇编代码)及其测试程序；
>
> crypto/md2：md2摘要实现及其测试程序；
>
> crypto/mdc2：mdc2摘要实现及其测试程序；
>
> crypto/md4：md4摘要实现及其测试程序；
>
> crypto/md5：md5摘要实现及其测试程序；
>
> crypto/sha：sha、sha1、sha256、sha512实现及其测试程序(包含汇编源码)。

上述各种摘要源码在openssl中都是底层的函数，相对独立，能单独提取出来，而不必包含openssl的libcrypto库(因为这个库一般比较大)。

 

## 15.3  函数说明

所有的摘要算法都有如下几个函数：

1. XXX_Init

   XXX为具体的摘要算法名称，该函数初始化上下文，用于多数据摘要。

2. XXX_Update

   XXX为具体的摘要算法名称，进行摘要计算，该函数可运行多次，对多个数据摘要。

3. XXX_Final

   XXX为具体的摘要算法名称，进行摘要计算，该函数与1)和2）一起用。

4. XXX

   对一个数据进行摘要。该函数由上述1、2和3实现，只是XXX_Update只调用一次。对应源码为XXX_one.c。

   这些函数的测试程序，可参考各个目录下对应的测试程序源码。

## 15.4  编程示例

​	以下示例了MD2、MD4、MD5、SHA和SHA1函数的使用方法：

```cpp
#include <openssl/md2.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>
int main() {
    unsigned char in[] = "3dsferyewyrtetegvbzVEgarhaggavxcv";
    unsigned char out[20];
    size_t n;
    int i;
    n = strlen((const char*)in);
#ifdef OPENSSL_NO_MDC2
    printf("默认openssl安装配置无MDC2\n");
#else
    MDC2(in, n, out);
    printf("MDC2 digest result :\n");
    for (i = 0; i < 16; i++)
        printf("%x ", out[i]);
#endif
    RIPEMD160(in, n, out);
    printf("RIPEMD160 digest result :\n");
    for (i = 0; i < 20; i++)
        printf("%x ", out[i]);
    MD2(in, n, out);
    printf("MD2 digest result :\n");
    for (i = 0; i < 16; i++)
        printf("%x ", out[i]);
    MD4(in, n, out);
    printf("\n\nMD4 digest result :\n");
    for (i = 0; i < 16; i++)
        printf("%x ", out[i]);
    MD5(in, n, out);
    printf("\n\nMD5 digest result :\n");
    for (i = 0; i < 16; i++)
        printf("%x ", out[i]);
    SHA(in, n, out);
    printf("\n\nSHA digest result :\n");
    for (i = 0; i < 20; i++)
        printf("%x ", out[i]);
    SHA1(in, n, out);
    printf("\n\nSHA1 digest result :\n");
    for (i = 0; i < 20; i++)
        printf("%x ", out[i]);
    SHA256(in, n, out);
    printf("\n\nSHA256 digest result :\n");
    for (i = 0; i < 32; i++)
        printf("%x ", out[i]);
    SHA512(in, n, out);
    printf("\n\nSHA512 digest result :\n");
    for (i = 0; i < 64; i++)
        printf("%x ", out[i]);
    printf("\n");
    return 0;
}
```

​	以上示例中演示了各种摘要计算函数的使用方法。对输入数据in进行摘要计算，结果存放在out缓冲区中。其中：

* mdc2、md4和md5摘要结果为16字节，128比特；
* ripemd160、sha和sha1摘要结果为20字节，160bit；
* sha256摘要结果为32字节，256bit；
* sha512摘要结果为64字节，512bit。

## 15.5  HMAC

​	HMAC用于保护消息的完整性，它采用摘要算法对消息、填充以及秘密密钥进行混合运算。在消息传输时，用户不仅传送消息本身，还传送HMAC值。接收方接收数据后也进行HMAC运算，再比对MAC值是否一致。由于秘密密钥只有发送方和接收方才有，其他人不可能伪造假的HMAC值，从而能够知道消息是否被篡改。

​	ssl协议中用HMAC来保护发送消息，并且ssl客户端和服务端的HMAC密钥是不同的，即对于双方都有一个读MAC保护密钥和写MAC保护密钥。

​	HMAC的实现在crypto/hmac/hmac.c中，如下：

```cpp
unsigned char* HMAC(const EVP_MD* evp_md, const void* key, int key_len, const unsigned char* d,
                    size_t n, unsigned char* md, unsigned int* md_len) {
    HMAC_CTX c;
    static unsigned char m[EVP_MAX_MD_SIZE];
    if (md == NULL)
        md = m;
    HMAC_CTX_init(&c);
    HMAC_Init(&c, key, key_len, evp_md);
    HMAC_Update(&c, d, n);
    HMAC_Final(&c, md, md_len);
    HMAC_CTX_cleanup(&c);
    return (md);
}
```

* evp_md指明HMAC使用的摘要算法；
* key为秘密密钥指针地址；
* key_len为秘密密钥的长度；
* d为需要做HMAC运算的数据指针地址；
* n为d的长度；
* md用于存放HMAC值；
* md_len为HMAC值的长度。
