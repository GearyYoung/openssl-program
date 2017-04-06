# 第三十章 PKCS12

## 30.1  概述

​	pkcs12 (个人数字证书标准)用于存放用户证书、crl、用户私钥以及证书链。pkcs12中的私钥是加密存放的。

## 30.2  openss实现

​	openssl的pkcs12实现在crypto/pkcs12目录，有如下源码：

* p12_add.c：处理PKCS12_SAFEBAG，PKCS12_SAFEBAG用于存放证书和私钥相关的信息；
* p12_attr.c：属性处理；
* p12_crt：生成一个完整的pkcs12；
* p12_init.c：构造一个pkcs12数据结构；
* p12_kiss.c：解析pkcs12结构，获取证书和私钥等信息；
* p12_npas：设置新口令；
* p12_p8e.c：加密处理用户私钥(pkcs8格式)；
* p12_p8d.c：解密出用户私钥；
* pk12err.c：错误处理；
* p12_asn.c：pkcs12各个数据结构的DER编解码实现；
* p12_crpt.c：pkcs12的pbe(基于口令的加密)函数；
* p12_decr.c.c：pkcs12的pbe解密；
* p12_key.c：根据用户口令生成对称密钥；
* p12_mutl.c：pkcs12的MAC信息处理；
* p12_utl.c：一些通用的函数。

## 30.3数据结构

​	数据结构定义在crypto/pkcs12/pkcs12.h中，如下所示：

1. PKCS12_MAC_DATA

```cpp
typedef struct {
    X509_SIG* dinfo;
    ASN1_OCTET_STRING* salt;
    ASN1_INTEGER* iter;
} PKCS12_MAC_DATA;
```

​	该结构用于存放pkcs12中的MAC信息，防止他人篡改。xinfo用于存放MAC值和摘要算法，salt和iter用于根据口令来生成对称密钥(pbe)。

2. PKCS12

```cpp
typedef struct {
    ASN1_INTEGER* version;
    PKCS12_MAC_DATA* mac;
    PKCS7* authsafes;
} PKCS12;
```

​	pkcs12数据结构，version为版本，mac用于存放MAC信息以及对称密钥相关的信息authsafes为pkcs7结构，用于存放的证书、crl以及私钥等各种信息。

3. PKCS12_BAGS

```cpp
typedef struct pkcs12_bag_st {
    ASN1_OBJECT* type;
    union {
        ASN1_OCTET_STRING* x509cert;
        ASN1_OCTET_STRING* x509crl;
        ASN1_OCTET_STRING* octet;
        ASN1_IA5STRING* sdsicert;
        ASN1_TYPE* other;
    } value;
} PKCS12_BAGS;
```

​	该结构用于存放各种实体对象。

4. PKCS12_SAFEBAG

```cpp
typedef struct {
    ASN1_OBJECT* type;
    union {
        struct pkcs12_bag_st* bag;
        struct pkcs8_priv_key_info_st* keybag;
        X509_SIG* shkeybag;
        STACK_OF(PKCS12_SAFEBAG) * safes;
        ASN1_TYPE* other;
    } value;
    STACK_OF(X509_ATTRIBUTE) * attrib;
} PKCS12_SAFEBAG;
```

​	该结构用于存放各种证书、crl和私钥数据。

​	上述两种结构与pkcs7数据结构的相互转化可参考p12_add.c。在使用中，用户根据证书、私钥以及crl等信息来构造PKCS12_SAFEBAG数据结构，然后将这些结构转化为pkcs12中的pkcs7结构。

## 30.4函数

1. `int PKCS12_gen_mac(PKCS12 *p12, const char *pass, int passlen,     unsigned char *mac, unsigned int *maclen)`
   生成MAC值，pass为用户口令，passlen为口令长度，mac和maclen用于存放MAC值。当p12中pkcs7为数据类型时，本函数有效。

2. `int PKCS12_verify_mac(PKCS12 *p12, const char *pass, int passlen)`
   验证pkcs12的MAC，pass为用户口令，passlen为口令长度。PKCS12的MAC值存放在p12-> mac-> dinfo->digest中。本函数根据pass和passlen调用PKCS12_gen_mac生成一个MAC值，与p12中已有的值进行比较。

3. `PKCS12_create`
   成PKCS12数据结构。

4. `PKCS12_parse`
   解析PKCS12，得到私钥和证书等信息。

5. `PKCS12_key_gen_asc/PKCS12_key_gen_uni`
   生成pkcs12密钥，输入口令为ASCII码/UNICODE。

6. `unsigned char * PKCS12_pbe_crypt(X509_ALGOR *algor, const char *pass,int passlen, unsigned char *in, int inlen, unsigned char **data,int *datalen, int en_de)`
   PKCS12加解密，algor为对称算法，pass为口令，passlen为口令长度，in为输入数据，inlen为输入数据长度，data和datalen用于存放结果，en_de用于指明时加密还是解密。

7. `PKCS7 *PKCS12_pack_p7data(STACK_OF(PKCS12_SAFEBAG) *sk)`
   打包PKCS12_SAFEBAG堆栈，生成PKCS7数据结构并返回。

8. `PKCS12_unpack_p7data`
   上面函数的逆过程。

9. `PKCS12_pack_p7encdata`
   将PKCS12_SAFEBAG堆栈根据pbe算法、口令和salt加密，生成pkcs7并返回。

10. `PKCS12_unpack_p7encdata`
   上述过程的逆过程。

11. `int PKCS12_newpass(PKCS12 *p12, char *oldpass, char *newpass)`
   替换pkcs12的口令。

12. `PKCS12_setup_mac`
   设置pkcs12的MAC数据结构。

13. `PKCS12_set_mac`
   设置pkcs12的MAC信息。

14. `PKCS12_pack_authsafes`
   将pkcs7堆栈信息打包到pkcs12中。

15. `PKCS12_unpack_authsafes`
   上面函数的逆过程，从pkcs12中解出pkcs7堆栈，并返回。

16. `PKCS12 *PKCS12_init(int mode)`
   生成一个pkcs12数据结构，mode的值必须为NID_pkcs7_data，即pkcs12中的pkcs7类型必须是data类型。

17. `PKCS12_PBE_add`
   加载各种pbe算法。

18. `PKCS12_PBE_keyivgen`
   根据口令生成对称密钥，并做加解密初始化。

19. `PKCS12_item_pack_safebag`
   将输入的数据打包为PKCS12_SAFEBAG并返回。

20. `PKCS12_x5092certbag`
   将证书打包为PKCS12_SAFEBAG并返回。

21. `PKCS12_certbag2x509`
   上述过程的逆过程。

22. `PKCS12_x509crl2certbag`
   将crl打包为PKCS12_SAFEBAG并返回。

23. `PKCS12_certbag2x509crl`
   上述过程的逆过程。

24. `PKCS12_item_i2d_encrypt`
   将数据结构DER编码，然后加密，数据存放在ASN1_OCTET_STRING中并返回。

25. `PKCS12_item_decrypt_d2i`
   上面函数的逆过程，解密输入数据，然后DER解码出数据结构，并返回。

26. `int PKCS12_add_friendlyname_uni(PKCS12_SAFEBAG *bag,const unsigned char *name, int namelen)`
   给PKCS12_SAFEBAG添加一个属性，属性类型为NID_friendlyName，name为unicode编码。

27. `int PKCS12_add_friendlyname_asc(PKCS12_SAFEBAG *bag, const char *name,int namelen)`
   给PKCS12_SAFEBAG添加一个属性，属性类型为NID_friendlyName，name为ASCII码。

28. `PKCS12_get_friendlyname`
   上面函数的逆过程，返回一个ASCII码值。

29. `PKCS12_add_CSPName_asc`
   给PKCS12_SAFEBAG添加一个NID_ms_csp_name属性，输入参数为ASCII码。

30. `PKCS12_add_localkeyid`
   给PKCS12_SAFEBAG添加一个NID_localKeyID属性。

31. `PKCS12_MAKE_SHKEYBAG`
   将pkcs8密钥转化为PKCS12_SAFEBAG。

32. `PKCS8_PRIV_KEY_INFO *PKCS12_decrypt_skey(PKCS12_SAFEBAG *bag, const char *pass, int passlen)`
   上面函数的逆过程，从bag中提取pkcs8密钥信息。

   ​

## 30.5  编程示例

1. pkcs12解码

```cpp
#include <openssl/pkcs12.h>
#include <string.h>
int X509_ALGOR_print(BIO* bp, X509_ALGOR* signature) {
    int nid;
    unsigned char* p;
    PBEPARAM* pbe = NULL;
    nid = OBJ_obj2nid(signature->algorithm);
    switch (nid) {
    case NID_md5WithRSAEncryption:
        printf("md5WithRSAEncryption");
        break;
    case NID_sha1WithRSAEncryption:
        printf("sha1WithRSAEncryption");
        break;
    case NID_rsaEncryption:
        printf("rsaEncryption");
        break;
    case NID_sha1:
        printf("sha1");
        break;
    case NID_pbe_WithSHA1And3_Key_TripleDES_CBC:
        printf("NID_pbe_WithSHA1And3_Key_TripleDES_CBC");
        break;
    default:
        printf("unknown signature.");
        break;
    }
    if (signature->parameter != NULL) {
        if (nid == NID_pbe_WithSHA1And3_Key_TripleDES_CBC) {
            printf("算法参数:\n");
            p = signature->parameter->value.sequence->data;
            d2i_PBEPARAM(&pbe, &p, signature->parameter->value.sequence->length);
            printf("salt : \n");
            i2a_ASN1_INTEGER(bp, pbe->salt);
            printf("\n");
            printf("iter : %d\n", ASN1_INTEGER_get(pbe->iter));
        }
    }
    printf("\n");
    return 0;
}
void X509_SIG_print(BIO* bp, X509_SIG* a) {
    if (a->algor != NULL) {
        printf("算法:\n");
        X509_ALGOR_print(bp, a->algor);
    }
    if (a->digest != NULL) {
        printf("摘要:\n");
        i2a_ASN1_STRING(bp, a->digest, 1);
    }
}
void PKCS12_SAFEBAG_print(BIO* bp, PKCS12_SAFEBAG* bag) {
    int nid, attrnum, certl, len = 50, k, n, x;
    unsigned char *p, buf[50];
    PBEPARAM* pbe = NULL;
    X509_ATTRIBUTE* attr;
    ASN1_TYPE* type;
    X509* cert = NULL;
    nid = OBJ_obj2nid(bag->type);
    if ((nid == NID_pkcs8ShroudedKeyBag) ||
        (nid == NID_pbe_WithSHA1And3_Key_TripleDES_CBC)) /* pkcs 8 */
    {
        nid = OBJ_obj2nid(bag->value.shkeybag->algor->algorithm);
        if (nid == NID_pbe_WithSHA1And3_Key_TripleDES_CBC) {
            /* alg */
            X509_SIG_print(bp, bag->value.shkeybag);
        }
    } else if (nid == NID_certBag) {
        nid = OBJ_obj2nid(bag->value.bag->type);
        if (nid == NID_x509Certificate) {
            p = bag->value.bag->value.x509cert->data;
            certl = bag->value.bag->value.x509cert->length;
            d2i_X509(&cert, &p, certl);
            if (cert != NULL) {
                X509_print(bp, cert);
            }
        }
    }
    printf("attris : \n");
    attrnum = sk_X509_ATTRIBUTE_num(bag->attrib);
    for (k = 0; k < attrnum; k++) {
        attr = sk_X509_ATTRIBUTE_value(bag->attrib, k);
        nid = OBJ_obj2nid(attr->object);
        OBJ_obj2txt(buf, len, attr->object, 1);
        printf("object : %s,nid is %d\n", buf, nid);
        if (attr->single == 0) /* set */
        {
            n = sk_ASN1_TYPE_num(attr->value.set);
            for (x = 0; x < n; x++) {
                type = sk_ASN1_TYPE_value(attr->value.set, x);
                if ((type->type != V_ASN1_SEQUENCE) && (type->type != V_ASN1_SET)) {
                    if (type->type == V_ASN1_OCTET_STRING)
                        i2a_ASN1_INTEGER(bp, type->value.octet_string);
                    else
                        ASN1_STRING_print(bp, (ASN1_STRING*)type->value.ptr);
                }
            }
        }
        printf("\n");
    }
}
int main() {
    FILE* fp;
    PKCS12* p12 = NULL;
    PKCS7 *p7 = NULL, *one;
    unsigned char buf[10000], *p;
    int len, i, num, j, count, ret;
    STACK_OF(PKCS7) * p7s;
    STACK_OF(PKCS12_SAFEBAG) * bags;
    PKCS12_SAFEBAG* bag;
    PBEPARAM* pbe = 0;
    BIO* bp;
    char pass[100];
    int passlen;
    X509* cert = NULL;
    STACK_OF(X509)* ca = NULL;
    EVP_PKEY* pkey = NULL;
    fp = fopen("timeserver.pfx", "rb");
    len = fread(buf, 1, 10000, fp);
    fclose(fp);
    OpenSSL_add_all_algorithms();
    bp = BIO_new(BIO_s_file());
    BIO_set_fp(bp, stdout, BIO_NOCLOSE);
    p = buf;
    d2i_PKCS12(&p12, &p, len);
    printf("input password : \n");
    scanf("%s", pass);
    ret = PKCS12_parse(p12, pass, &pkey, &cert, &ca);
    if (ret != 1) {
        printf("err\n");
        return 0;
    }
    /* 私钥写入文件 */
    p = buf;
    len = i2d_PrivateKey(pkey, &p);
    fp = fopen("prikey.cer", "wb");
    fwrite(buf, 1, len, fp);
    fclose(fp);
    /* 修改密码 */
    ret = PKCS12_newpass(p12, pass, "test");
    fp = fopen("newpass.pfx", "wb");
    ret = i2d_PKCS12_fp(fp, p12);
    fclose(fp);
    /* version */
    printf("version : %d\n", ASN1_INTEGER_get(p12->version));
    /*  PKCS12_MAC_DATA */
    printf("PKCS12_MAC_DATA sig :\n");
    X509_SIG_print(bp, p12->mac->dinfo);
    printf("salt : \n");
    i2a_ASN1_STRING(bp, p12->mac->salt, 1);
    printf("iter : %d\n", ASN1_INTEGER_get(p12->mac->iter));
    /* p7s */
    p7s = PKCS12_unpack_authsafes(p12);
    num = sk_PKCS7_num(p7s);
    for (i = 0; i < num; i++) {
        one = sk_PKCS7_value(p7s, i);
        if (PKCS7_type_is_data(one)) {
            bags = PKCS12_unpack_p7data(one);
            count = sk_PKCS12_SAFEBAG_num(bags);
            for (j = 0; j < count; j++) {
                bag = sk_PKCS12_SAFEBAG_value(bags, j);
                PKCS12_SAFEBAG_print(bp, bag);
            }
        } else if (PKCS7_type_is_encrypted(one)) {
        back:
            printf("\ninput password :\n");
            scanf("%s", pass);
            passlen = strlen(pass);
            bags = PKCS12_unpack_p7encdata(one, pass, passlen);
            if (bags == NULL)
                goto back;
            printf("passwod is :%s\n", pass);
            count = sk_PKCS12_SAFEBAG_num(bags);
            for (j = 0; j < count; j++) {
                bag = sk_PKCS12_SAFEBAG_value(bags, j);
                PKCS12_SAFEBAG_print(bp, bag);
            }
        }
    }
    BIO_free(bp);
    sk_PKCS7_pop_free(p7s, PKCS7_free);
    PKCS12_free(p12);
    return 0;
}
```

​	采用PKCS12_parse函数，下面的例子用于解析pkcs12文件，获取证书，以及RSA密钥信息。

```cpp
int p12_parse(char* p12, int p12Len, char* pass, char* cert, int* certlen, char* n, int* nlen,
              char* e, int* elen, char* d, int* dlen, char* p, int* plen, char* q, int* qlen,
              char* dmp1, int* dmp1len, char* dmq1, int* dmq1len, char* iqmp, int* iqmplen) {
    int ret = 0, certl;
    char *pp = NULL, *certp = NULL, *derCert = NULL;
    BIO* bp = NULL;
    PKCS12* PK12 = NULL;
    EVP_PKEY* pkey = NULL;
    X509* cc = NULL;
    OpenSSL_add_all_algorithms();
    pp = p12;
    d2i_PKCS12(&PK12, &pp, p12Len);
    if (PK12 == NULL) {
        printf("d2i_PKCS12 err\n");
        return -1;
    }
    ret = PKCS12_parse(PK12, pass, &pkey, &cc, NULL);
    if (ret != 1) {
        printf("PKCS12_parse err\n");
        return -1;
    }
    /* cert */
    certl = i2d_X509(cc, NULL);
    certp = (char*)malloc(certl + 10);
    derCert = certp;
    certl = i2d_X509(cc, &certp);
    memcpy(cert, derCert, certl);
    *certlen = certl;
    free(derCert);
    /* n */
    *nlen = BN_bn2bin(pkey->pkey.rsa->n, n);
    /* e */
    *elen = BN_bn2bin(pkey->pkey.rsa->e, e);
    /* d */
    *dlen = BN_bn2bin(pkey->pkey.rsa->d, d);
    /* p */
    *plen = BN_bn2bin(pkey->pkey.rsa->p, p);
    /* q */
    *qlen = BN_bn2bin(pkey->pkey.rsa->q, q);
    /* dmp1 */
    *dmp1len = BN_bn2bin(pkey->pkey.rsa->dmp1, dmp1);
    /* dmq1 */
    *dmq1len = BN_bn2bin(pkey->pkey.rsa->dmq1, dmq1);
    /* iqmp */
    *iqmplen = BN_bn2bin(pkey->pkey.rsa->iqmp, iqmp);
    PKCS12_free(PK12);
    OPENSSL_free(PK12);
    return 0;
}
```

2. 生成pkcs12证书

```cpp
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
int main() {
    int ret, len, key_usage, iter, key_nid;
    PKCS12* p12;
    PKCS7* p7;
    STACK_OF(PKCS7) * safes;
    STACK_OF(PKCS12_SAFEBAG) * bags;
    PKCS12_SAFEBAG* bag;
    FILE* fp;
    unsigned char *buf, *p, tmp[5000];
    X509* cert = NULL;
    EVP_PKEY* pkey = NULL;
    OpenSSL_add_all_algorithms();
    p12 = PKCS12_init(NID_pkcs7_data);
    /*
    p12->mac=PKCS12_MAC_DATA_new();
    p12->mac->dinfo->algor->algorithm=OBJ_nid2obj(NID_sha1);
    ASN1_STRING_set(p12->mac->dinfo->digest,"aaa",3);
    ASN1_STRING_set(p12->mac->salt,"test",4);
    p12->mac->iter=ASN1_INTEGER_new();
    ASN1_INTEGER_set(p12->mac->iter,3);
    */
    /* pkcs7 */
    bags = sk_PKCS12_SAFEBAG_new_null();
    fp = fopen("time.cer", "rb");
    len = fread(tmp, 1, 5000, fp);
    fclose(fp);
    p = tmp;
    /* cert */
    d2i_X509(&cert, &p, len);
    bag = PKCS12_x5092certbag(cert);
    sk_PKCS12_SAFEBAG_push(bags, bag);
    /* private key */
    fp = fopen("prikey.cer", "rb");
    len = fread(tmp, 1, 5000, fp);
    fclose(fp);
    p = tmp;
    pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &p, len);
    PKCS12_add_key(&bags, pkey, KEY_EX, PKCS12_DEFAULT_ITER, NID_pbe_WithSHA1And3_Key_TripleDES_CBC,"openssl");
    p7 = PKCS12_pack_p7data(bags);
    safes = sk_PKCS7_new_null();
    sk_PKCS7_push(safes, p7);
    ret = PKCS12_pack_authsafes(p12, safes);
    len = i2d_PKCS12(p12, NULL);
    buf = p = malloc(len);
    len = i2d_PKCS12(p12, &p);
    fp = fopen("myp12.pfx", "wb");
    fwrite(buf, 1, len, fp);
    fclose(fp);
    printf("ok\n");
    return 0;
}
```

​	采用PKCS12_create函数：

```cpp
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
int main() {
    int ret, len, key_usage, iter, key_nid;
    PKCS12* p12;
    PKCS7* p7;
    STACK_OF(PKCS7) * safes;
    STACK_OF(PKCS12_SAFEBAG) * bags;
    PKCS12_SAFEBAG* bag;
    FILE* fp;
    unsigned char *buf, *p, tmp[5000];
    X509* cert = NULL;
    EVP_PKEY* pkey = NULL;
    OpenSSL_add_all_algorithms();
    fp = fopen("time.cer", "rb");
    len = fread(tmp, 1, 5000, fp);
    fclose(fp);
    p = tmp;
    /* cert */
    d2i_X509(&cert, &p, len);
    /* private key */
    fp = fopen("prikey.cer", "rb");
    len = fread(tmp, 1, 5000, fp);
    fclose(fp);
    p = tmp;
    pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &p, len);
    p12 = PKCS12_create("ossl", "friend name", pkey, cert, NULL,NID_pbe_WithSHA1And3_Key_TripleDES_CBC, NID_pbe_WithSHA1And40BitRC2_CBC,PKCS12_DEFAULT_ITER, -1, KEY_EX);
    len = i2d_PKCS12(p12, NULL);
    buf = p = malloc(len);
    len = i2d_PKCS12(p12, &p);
    fp = fopen("myp12.pfx", "wb");
    fwrite(buf, 1, len, fp);
    fclose(fp);
    printf("ok\n");
    return 0;
}
```

