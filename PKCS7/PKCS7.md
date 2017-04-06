# 第二十九章 PKCS7

## 29.1概述

​	加密消息语法（pkcs7），是各种消息存放的格式标准。这些消息包括：数据、签名数据、数字信封、签名数字信封、摘要数据和加密数据。

## 29.2  数据结构

​	Openssl的pkcs7实现在crypto/pkcs7目录下。pkcs7的各种消息数据结构和函数在crypto/pkcs7/pkcs7.h中定义，主要数据结构如下：

```cpp
typedef struct pkcs7_st {
    /* 其他项 */
    ASN1_OBJECT* type;
    union {
        char* ptr;
        /* NID_pkcs7_data */
        ASN1_OCTET_STRING* data;
        /* NID_pkcs7_signed */
        PKCS7_SIGNED* sign;
        /* NID_pkcs7_enveloped */
        PKCS7_ENVELOPE* enveloped;
        /* NID_pkcs7_signedAndEnveloped */
        PKCS7_SIGN_ENVELOPE* signed_and_enveloped;
        /* NID_pkcs7_digest */
        PKCS7_DIGEST* digest;
        /* NID_pkcs7_encrypted */
        PKCS7_ENCRYPT* encrypted;
        /* Anything else */
        ASN1_TYPE* other;
    } d;
} PKCS7;
```

​	其中type用于表示是何种类型的pkcs7消息，data、sign、enveloped、signed_and_enveloped、digest和ncrypted对于了6种不同的具体消息。oher用于存放任意数据类型（也可以是pkcs7结构），所以，本结构可以是一个嵌套的数据结构。

​	pkcs7各种类型数据结构的DER编解码通过宏在crypto/pkcs7/pk7_asn1.c中实现，包括new、free、i2d和d2i函数。

## 29.3  函数

1. `PKCS7_add_attrib_smimecap`
   给`PKCS7_SIGNER_INFO`添加`NID_SMIMECapabilities`属性。
2. `int PKCS7_add_attribute(PKCS7_SIGNER_INFO *p7si, int nid, int atrtype,void *value)`
   给PKCS7_SIGNER_INFO添加属性，nid为属性类型，value为属性的ASN1数据结构，atrtype为value的ASN1类型。
3. `int PKCS7_add_certificate(PKCS7 *p7, X509 *x509)`
   将证书添加到PKCS7对应消息的证书堆栈中，只对NID_pkcs7_signed和NID_pkcs7_signedAndEnveloped两种类型有效。
4. `PKCS7_add_crl`
   将crl添加到PKCS7对应消息的crl堆栈中，只对NID_pkcs7_signed和NID_pkcs7_signedAndEnveloped两种类型有效。
5. `PKCS7_add_recipient`/`PKCS7_add_recipient_info`
   添加接收者信息。
6. `PKCS7_add_signer`
   添加一个签名者信息。
7. `KCS7_add_signed_attribute`
   给PKCS7_SIGNER_INFO添加属性。
8. `PKCS7_cert_from_signer_info`
   从pkcs7消息中根据颁发者和证书序列号获取证书。
9. `PKCS7_ctrl`
   控制函数。
10. `PKCS7_dataDecode`
   解析输入的pkcs7消息，将结果存入BIO链表并返回。
11. `PKCS7_dataInit`/`PKCS7_dataFinal`
   解析输入的pkcs7消息，将结果存入BIO。
12. `PKCS7_dataVerify`
   验证pkcs7数据。
13. `PKCS7_sign`
   签名pkcs7消息。
   14)  `PKCS7_verify`
   验证pkcs7消息。
14. `PKCS7_set_type`
   设置pkcs7消息类型。
15. `PKCS7_dup`
   拷贝pkcs7结构。

## 29.4  消息编解码

​	PKCS7编码时调用函数i2d_PKCS7，在调用此函数之前，需要填充其内部数据结构。PKCS7解码时调用函数d2i_PKCS7获取内部数据结构。

​	下面是一些编码的示例。

###  29.4.1 data

```cpp
/* pkcs7  data */
#include <openssl/objects.h>
#include <openssl/pkcs7.h>
#include <string.h >
int main() {
    PKCS7* p7;
    int len;
    char buf[1000], *der, *p;
    FILE* fp;
    p7 = PKCS7_new();
    PKCS7_set_type(p7, NID_pkcs7_data);
    strcpy(buf, "pkcs7 data !\n");
    len = strlen(buf);
    ASN1_OCTET_STRING_set(p7->d.data, (const unsigned char*)buf, len);
    len = i2d_PKCS7(p7, NULL);
    der = (char*)malloc(len);
    p = der;
    len = i2d_PKCS7(p7, (unsigned char**)&amp; p);
    fp = fopen("p7_data.cer", "wb");
    fwrite(der, 1, len, fp);
    fclose(fp);
    PKCS7_free(p7);
    free(der);
    return 0;
}
```

​	本例用于生成data类型的pkcs7消息。

### 29.4.2  signed data

```cpp
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
int main() {
    PKCS7* p7;
    int len;
    unsigned char *der, *p;
    FILE* fp;
    X509* x;
    BIO* in;
    X509_ALGOR* md;
    PKCS7_SIGNER_INFO* si;
    p7 = PKCS7_new();
    PKCS7_set_type(p7, NID_pkcs7_signed);
    p7->d.sign->cert = sk_X509_new_null();
    in = BIO_new_file("b64cert.cer", "r");
    x = PEM_read_bio_X509(in, NULL, NULL, NULL);
    sk_X509_push(p7->d.sign->cert, x);
    md = X509_ALGOR_new();
    md->algorithm = OBJ_nid2obj(NID_md5);
    sk_X509_ALGOR_push(p7->d.sign->md_algs, md);
    si = PKCS7_SIGNER_INFO_new();
    ASN1_INTEGER_set(si->version, 2);
    ASN1_INTEGER_set(si->issuer_and_serial->serial, 333);
    sk_PKCS7_SIGNER_INFO_push(p7->d.sign->signer_info, si);
    len = i2d_PKCS7(p7, NULL);
    der = (unsigned char*)malloc(len);
    p = der;
    len = i2d_PKCS7(p7, p);
    fp = fopen("p7_sign.cer", "wb");
    fwrite(der, 1, len, fp);
    fclose(fp);
    free(der);
    PKCS7_free(p7);
    return 0;
}
```

​	本例用于生成signed类型的pkcs7消息。

###  29.4.3  enveloped

```cpp
#include <openssl/objects.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
int main() {
    PKCS7* p7;
    int len;
    char *der, *p;
    FILE* fp;
    PKCS7_RECIP_INFO* inf;
    p7 = PKCS7_new();
    PKCS7_set_type(p7, NID_pkcs7_enveloped);
    ASN1_INTEGER_set(p7->d.enveloped->version, 3);
    inf = PKCS7_RECIP_INFO_new();
    ASN1_INTEGER_set(inf->version, 4);
    ASN1_INTEGER_set(inf->issuer_and_serial->serial, 888888);
    inf->key_enc_algor->algorithm = OBJ_nid2obj(NID_des_ede3_cbc);
    ASN1_OCTET_STRING_set(inf->enc_key, (const unsigned char*)"key info....", 12);
    sk_PKCS7_RECIP_INFO_push(p7->d.enveloped->recipientinfo, inf);
    p7->d.enveloped->enc_data->algorithm->algorithm = OBJ_nid2obj(NID_des_ede3_cbc);
    p7->d.enveloped->enc_data->enc_data = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(p7->d.enveloped->enc_data->enc_data, (const unsigned char*)"info....", 8);
    len = i2d_PKCS7(p7, NULL);
    der = (char*)malloc(len);
    p = der;
    len = i2d_PKCS7(p7, (unsigned char**)p);
    fp = fopen("p7_evveloped.cer", "wb");
    fwrite(der, 1, len, fp);
    fclose(fp);
    PKCS7_free(p7);
    free(der);
    return 0;
}
```

​	本例用于生成enveloped类型的pkcs7消息。

### 29.4.4  signed_and_enveloped

```cpp
#include <openssl/objects.h>
#include <openssl/pkcs7.h>
int main() {
    PKCS7* p7;
    int len;
    char *der, *p;
    FILE* fp;
    p7 = PKCS7_new();
    PKCS7_set_type(p7, NID_pkcs7_signedAndEnveloped);
    len = i2d_PKCS7(p7, NULL);
    der = (char*)malloc(len);
    p = der;
    len = i2d_PKCS7(p7, (unsigned char**)p);
    fp = fopen("p7_singAndEnv.cer", "wb");
    fwrite(der, 1, len, fp);
    fclose(fp);
    PKCS7_free(p7);
    free(der);
    return 0;
}
```

​	本例用于生成signedAndEnveloped类型的pkcs7消息,不过省略了数据结构的填充。

### 29.4.5  digest

```cpp
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
int main() {
    PKCS7* p7;
    int ret;
    BIO* b;
    p7 = PKCS7_new();
    ret = PKCS7_set_type(p7, NID_pkcs7_digest);
    b = BIO_new_file("p7Digest.pem", "w");
    PEM_write_bio_PKCS7(b, p7);
    BIO_free(b);
    PKCS7_free(p7);
    return 0;
}
```

​	本例用于生成digest类型的pkcs7消息,并以PEM格式存储。

### 29.4.6  encrypted

```cpp
#include <openssl/objects.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
int main() {
    PKCS7* p7;
    int ret, len;
    char *der, *p;
    FILE* fp;
    p7 = PKCS7_new();
    ret = PKCS7_set_type(p7, NID_pkcs7_encrypted);
    ASN1_INTEGER_set(p7->d.encrypted->version, 3);
    p7->d.encrypted->enc_data->algorithm->algorithm = OBJ_nid2obj(NID_des_ede3_cbc);
    p7->d.encrypted->enc_data->enc_data = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(p7->d.encrypted->enc_data->enc_data, (const unsigned char*)"3434", 4);
    len = i2d_PKCS7(p7, NULL);
    der = (char*)malloc(len);
    p = der;
    len = i2d_PKCS7(p7, (unsigned char**)p);
    fp = fopen("p7_enc.cer", "wb");
    fwrite(der, 1, len, fp);
    fclose(fp);
    PKCS7_free(p7);
    free(der);
    return 0;
}
```

​	本例用于生成encrypted类型的pkcs7消息。

### 29.4.7  读取PEM

```cpp
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
int main() {
    BIO* b;
    PKCS7* p7;
    b = BIO_new_file("p7Digest.pem", "r");
    p7 = PEM_read_bio_PKCS7(b, NULL, NULL, NULL);
    BIO_free(b);
    PKCS7_free(p7);
    return 0;
}
```

​	本例用于读取PEM格式的PKCS7数据。

### 29.4.8  解码pkcs7

```cpp
#include <openssl/objects.h>
#include <openssl/pkcs7.h>
int main() {
    PKCS7* p7 = NULL;
    int ret, len;
    char buf[1000], *p, name[1000];
    FILE* fp;
    fp = fopen("p7_sign.cer", "rb");
    len = fread(buf, 1, 1000, fp);
    fclose(fp);
    p = buf;
    d2i_PKCS7(p7, (const unsigned char**)p, len);
    ret = OBJ_obj2txt(name, 1000, p7->type, 0);
    printf("type : %s \n", name);
    PKCS7_free(p7);
    return 0;
}
```

​	本例解码DER格式的PKCS7消息。

