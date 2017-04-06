# 第二十八章 CRL

## 28.1  CRL介绍

​	证书撤销列表(Certificate Revocation List，简称CRL)，是一种包含撤销的证书列表的签名数据结构。CRL是证书撤销状态的公布形式，CRL就像信用卡的黑名单，用于公布某些数字证书不再有效。

​	CRL是一种离线的证书状态信息。它以一定的周期进行更新。CRL可以分为完全CRL和增量CRL。在完全CRL中包含了所有的被撤销证书信息，增量CRL由一系列的CRL来表明被撤销的证书信息，它每次发布的CRL是对前面发布CRL的增量扩充。

​	基本的CRL信息有：被撤销证书序列号、撤销时间、撤销原因、签名者以及CRL签名等信息。

​	基于CRL的验证是一种不严格的证书认证。CRL能证明在CRL中被撤销的证书是无效的。但是，它不能给出不在CRL中的证书的状态。如果执行严格的认证，需要采用在线方式进行认证，即OCSP认证。

## 28.2  数据结构

​	Openssl中的crl数据结构定义在crypto/x509/x509.h中。

1. X509_REVOKED

```cpp
typedef struct X509_revoked_st {
    ASN1_INTEGER* serialNumber; // 被撤销证书的序列号
    ASN1_TIME* revocationDate; // 撤销时间
    STACK_OF(X509_EXTENSION) * extensions; // 撤销时间
    int sequence; // 顺序号，用于排序，表示当前被撤销证书信息在crl中的顺序
} X509_REVOKED;
```

2. X509_CRL_INFO

```cpp
typedef struct X509_crl_info_st {
    ASN1_INTEGER* version;                  // crl版本
    X509_ALGOR* sig_alg;                    // crl签名法
    X509_NAME* issuer;                      // 签发者信息
    ASN1_TIME* lastUpdate;                  // 上次更新时间
    ASN1_TIME* nextUpdate;                  // 下次更新时间
    STACK_OF(X509_REVOKED) * revoked;       //被撤销证书信息
    STACK_OF(X509_EXTENSION) * extensions;  // 扩展项，可选
    ASN1_ENCODING enc;
} X509_CRL_INFO;
```

3. X509_CRL

```cpp
struct X509_crl_st {
    X509_CRL_INFO* crl;          //信息主体
    X509_ALGOR* sig_alg;         //签名算法，与X509_CRL_INFO中的一致
    ASN1_BIT_STRING* signature;  //签名值
    int references;              //引用
};
```

​	上述三个结构的DER编解码通过宏在crypto/asn1/x_crl.c中实现，包括new、free、i2d和d2i函数。

## 28.3  CRL函数

       CRL函数主要是set和get函数，如下：

1. `int X509_CRL_add0_revoked(X509_CRL *crl, X509_REVOKED *rev)`
   添加一个被撤销证书的信息。
2. `int X509_CRL_print(BIO *bp,X509_CRL *x)`
   打印crl内容到BIO中。
3. `int X509_CRL_print_fp(FILE *fp, X509_CRL *x)`
   将crl的内容输出到fp中，此函数调用了X509_CRL_print。
4. `int X509_CRL_set_issuer_name(X509_CRL *x, X509_NAME *name)`
   设置crl的颁发者。
5. `int X509_CRL_set_lastUpdate(X509_CRL *x, ASN1_TIME *tm)`
   设置crl上次发布时间。
6. `int X509_CRL_set_nextUpdate(X509_CRL *x, ASN1_TIME *tm)`
   设置crl下次发布时间。
7. `int X509_CRL_set_version(X509_CRL *x, long version)`
   设置crl版本。
8. `int X509_CRL_sign(X509_CRL *x, EVP_PKEY *pkey, const EVP_MD *md)`
   对crl进行签名，pkey为私钥，md为摘要算法，结果存放在x-> signature中。
9. `int X509_CRL_sort(X509_CRL *c)`
   根据证书序列号对crl排序，此函数实现采用了堆栈排序，堆栈的比较函数为`X509_REVOKED_cmp(crypto/asn1/x_crl.c)`。
10. `int X509_CRL_add1_ext_i2d(X509_CRL *x, int nid, void *value, int crit,unsigned long flags)`
   添加CRL扩展，nid为要添加的扩展标识，value为被添加的具体扩展项的内部数据结构地址，crit表明是否为关键扩展，flags表明何种操作。此函数调用X509V3_add1_i2d函数。
11. `int X509_CRL_add_ext(X509_CRL *x, X509_EXTENSION *ex, int loc)`
   添加扩展项到指定堆栈位置，此函数调用X509v3_add_ext，进行堆栈插入操作。
12. `int X509_CRL_cmp(const X509_CRL *a, const X509_CRL *b)`
   CRL比较，此函数调用X509_NAME_cmp，只比较颁发者的名字是否相同。
13. `X509_EXTENSION *X509_CRL_delete_ext(X509_CRL *x, int loc)`
   删除CRL扩展项堆栈中的某一项，loc指定被删除项在堆栈中的位置。
14. `int X509_CRL_digest(const X509_CRL *data, const EVP_MD *type,unsigned char *md, unsigned int *len)`
   CRL摘要，本函数对X509_CRL进行摘要，type指定摘要算法，摘要结果存放在md中，len表明摘要结果长度。
15. `X509_CRL_dup`
   CRL数据拷贝，此函数通过宏来实现。大部分ASN1类型数据都有dup函数，它们的实现方式比较简单：将对象DER编码，然后再解码，这样就实现了ASN1数据的复制。
16. `void *X509_CRL_get_ext_d2i(X509_CRL *x, int nid, int *crit, int *idx)`
   CRL中的获取扩展项，此函数用于获取crl中指定扩展项的内部数据结构，返回值为具体的扩展项数据结构地址，nid为扩展项标识，它调用了X509V3_get_d2i函数。
17. `int X509_CRL_get_ext_by_critical(X509_CRL *x, int crit, int lastpos)`
   获取扩展项在其堆栈中的位置，crit为扩展项是否关键标识，lastpos为堆栈搜索起始位置。此函数调用了X509v3_get_ext_by_critical。
18. `int X509_CRL_get_ext_by_NID(X509_CRL *x, int nid, int lastpos)`
   获取扩展项在其堆栈中的位置，nid为扩展项标识，lastpos为搜索起始位置。如果找到此扩展项，返回其在堆栈中的位置。
19. `int X509_CRL_get_ext_by_OBJ(X509_CRL *x, ASN1_OBJECT *obj, int lastpos)`
   同上。
20. `int X509_CRL_get_ext_count(X509_CRL *x)`
   获取crl中扩展项的个数。
21. `int X509_CRL_verify(X509_CRL *a, EVP_PKEY *r)`
   验证CRL。EVP_PKEY结构r中需要给出公钥。

## 28.4  编程示例

​	下面的例子用来生成一个crl文件。

```cpp
#include <openssl/x509.h>
int main() {
    int ret, len;
    unsigned char *buf, *p;
    unsigned long e = RSA_3;
    FILE* fp;
    time_t t;
    X509_NAME* issuer;
    ASN1_TIME *lastUpdate, *nextUpdate, *rvTime;
    X509_CRL* crl = NULL;
    X509_REVOKED* revoked;
    EVP_PKEY* pkey;
    ASN1_INTEGER* serial;
    RSA* r;
    BIGNUM* bne;
    BIO* bp;
    bne = BN_new();
    ret = BN_set_word(bne, e);
    r = RSA_new();
    ret = RSA_generate_key_ex(r, 1024, bne, NULL);
    if (ret != 1) {
        printf("RSA_generate_key_ex err!\n");
        return -1;
    }
    pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, r);
    crl = X509_CRL_new();
    ret = X509_CRL_set_version(crl, 3);
    issuer = X509_NAME_new();
    ret = X509_NAME_add_entry_by_NID(issuer, NID_commonName, V_ASN1_PRINTABLESTRING, CRLissuer, 10, -1, 0);
    ret = X509_CRL_set_issuer_name(crl, issuer);
    lastUpdate = ASN1_TIME_new();
    time(NULL);
    ASN1_TIME_set(lastUpdate, t);
    ret = X509_CRL_set_lastUpdate(crl, lastUpdate);
    /* 设置下次发布时间*/
    nextUpdate = ASN1_TIME_new();
    t = time(NULL);
    ASN1_TIME_set(nextUpdate, t + 1000);
    ret = X509_CRL_set_nextUpdate(crl, nextUpdate);
    /* 添加被撤销证书序列号*/
    revoked = X509_REVOKED_new();
    serial = ASN1_INTEGER_new();
    ret = ASN1_INTEGER_set(serial, 1000);
    ret = X509_REVOKED_set_serialNumber(revoked, serial);
    rvTime = ASN1_TIME_new();
    t = time(NULL);
    ASN1_TIME_set(rvTime, t + 2000);
    ret = X509_CRL_set_nextUpdate(crl, rvTime);
    ret = X509_REVOKED_set_revocationDate(revoked, rvTime);
    ret = X509_CRL_add0_revoked(crl, revoked);
    /* 排序*/
    ret = X509_CRL_sort(crl);
    /* 签名*/
    ret = X509_CRL_sign(crl, pkey, EVP_md5());
    /* 写入文件*/
    bp = BIO_new(BIO_s_file());
    BIO_set_fp(bp, stdout, BIO_NOCLOSE);
    X509_CRL_print(bp, crl);
    len = i2d_X509_CRL(crl, NULL);
    buf = malloc(len + 10);
    p = buf;
    len = i2d_X509_CRL(crl, &amp; p);
    fp = fopen("crl.crl", "wb");
    fwrite(buf, 1, len, fp);
    fclose(fp);
    BIO_free(bp);
    X509_CRL_free(crl);
    free(buf);
    getchar();
    return 0;
}
```

