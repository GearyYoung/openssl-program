# 第二十二章 PEM格式

## 22.1  PEM概述  

​	Openssl使用PEM（**Privacy Enhanced Mail**）格式来存放各种信息，它是openssl默认采用的信息存放方式。Openssl中的PEM文件一般包含如下信息：

1. 内容类型

   表明本文件存放的是什么信息内容，它的形式为“——-BEGIN XXXX ——”，与结尾的“——END XXXX——”对应。

2. 头信息   

   表明数据是如果被处理后存放，openssl中用的最多的是加密信息，比如加密算法以及初始化向量iv。

3. 信息体

   为BASE64编码的数据。

举例如下：

```log
—–BEGIN RSA PRIVATE KEY—–
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,9CFD51EC6654FCC3
g2UP/2EvYyhHKAKafwABPrQybsxnepPXQxpP9qkaihV3k0uYJ2Q9qD/nSV2AG9Slqp0HBomnYS35NSB1bmMb+oGD5vareO7Bt+XZgFv0FINCclTBsFOmZwqs/m95Af+BBkCvNCct+ngM+UWB2N8jXYnbDMvZGyI3ma+Sfcf3vX7gyPOEXgr5D5NgwwNyu/LtQZvM4k2f7xn7VcAFGmmtvAXvqVrhEvk55XR0plkc+nOqYXbwLjYMO5LSLFNAtETm9aw0nYMD0Zx+s+8tJdtPq+Ifu3g9UZkvh2KpEg7he8Z8vaV7lpHiTjmpgkKpx9wKUCHnJq8U3cNcYdRvCWNf4T2jYLSS4kxdK2p50KjH8xcfWXVkU2CK9NQGlh18TmPueZOkSEHf76KTE9DWKAo7mNmcByTziyofe5qKhtqkYYVBbaCFC0+pKTak4EuLgznt6j87ktuXDXFc+50DnWi1FtQN3LuQH5htl7autzaxCvenfGQByIh7gxCygBVCJdWca3xE1H0SbRV6LbtjeB/NdCvwgJsRLBXXkjU2TKy/ljsG29xHP2xzlvOtATxq1zMMwMKt7kJMFpgSTIbxgUeqzgGbR7VMBmWSF4bBNnGDkOQ0WLJhVq9OMbzpBzmGJqHn3XjZ2SPXF4xhC7ZhAMxDsFs35P4lPLDH/ycLTcLtUmVZJzvPvzh2r56iTiU28f/rMnHn1xQ92Cf+62VgECI6CwTotMeM0EfGdCQCiWjeqrzH9qy8+VN3Q2xIlUZj7ibO59YO1A5zVxpKcQRamwyIy/IYTPr2c2wLfsTZPBt6mD4=
—–END RSA PRIVATE KEY—–
```

​	本例是作者生成的一个RSA密钥，以PEM格式加密存放，采用了openssl默认的对称加密算法。其中，“—–BEGIN RSA PRIVATE KEY—–”表明了本文件是一个RSA私钥；DES-EDE3-CB为对称加密算法，9CFD51EC6654FCC3为对称算法初始化向量iv。

## 22.2  openssl的PEM实现

​	Openssl的PEM模块实现位于crypto/pem目录下，并且还依赖于openssl的ASN1模块。Openssl支持的PEM类型在crypto/pem/pem.h中定义如下：

```cpp
#define PEM_STRING_X509_OLD			“X509 CERTIFICATE”
#define PEM_STRING_X509				“CERTIFICATE”
#define PEM_STRING_X509_PAIR		“CERTIFICATE PAIR”
#define PEM_STRING_X509_TRUSTED		“TRUSTED CERTIFICATE”
#define PEM_STRING_X509_REQ_OLD		“NEW CERTIFICATE REQUEST”
#define PEM_STRING_X509_REQ			“CERTIFICATE REQUEST”
#define PEM_STRING_X509_CRL			“X509 CRL”
#define PEM_STRING_EVP_PKEY			“ANY PRIVATE KEY”
#define PEM_STRING_PUBLIC			“PUBLIC KEY”
#define PEM_STRING_RSA				“RSA PRIVATE KEY”
#define PEM_STRING_RSA_PUBLIC		“RSA PUBLIC KEY”
#define PEM_STRING_DSA				“DSA PRIVATE KEY”
#define PEM_STRING_DSA_PUBLIC		“DSA PUBLIC KEY”
#define PEM_STRING_PKCS7			“PKCS7”
#define PEM_STRING_PKCS8			“ENCRYPTED PRIVATE KEY”
#define PEM_STRING_PKCS8INF			“PRIVATE KEY”
#define PEM_STRING_DHPARAMS			“DH PARAMETERS”
#define PEM_STRING_SSL_SESSION		“SSL SESSION PARAMETERS”
#define PEM_STRING_DSAPARAMS		“DSA PARAMETERS”
#define PEM_STRING_ECDSA_PUBLIC		“ECDSA PUBLIC KEY”
#define PEM_STRING_ECPARAMETERS		“EC PARAMETERS”
#define PEM_STRING_ECPRIVATEKEY		“EC PRIVATE KEY”
```

​	Openssl生成PEM格式文件的大致过程如下：

1. 将各种数据DER编码；
2. 将1中的数据进行加密处理（如果需要）；
3. 根据类型以及是否加密，构造PEM头；
4. 将2中的数据进行BASE64编码，放入PEM文件。

​	Openssl各个类型的PEM处理函数主要是write和read函数。write函数用于生成PEM格式的文件，而read函数主要用于读取PEM格式的文件。各种类型的调用类似。

## 22.3  PEM函数

​	PEM函数定义在crypto/pem.h中。函数比较简单，主要的函数有：

1. PEM_write_XXXX/PEM_write_bio_XXXX

   将XXXX代表的信息类型写入到文件/bio中。

2. PEM_read_XXXX/PEM_read_bio_XXXX

   从文件/bio中读取PEM的XXXX代表类型的信息。

   XXXX可用代表的有：SSL_SESSION、X509、X509_REQ、X509_AUX、X509_CRL、RSAPrivateKey、RSAPublicKey、DSAPrivateKey、PrivateKey、PKCS7、DHparams、NETSCAPE_CERT_SEQUENCE、PKCS8PrivateKey、DSAPrivateKey、DSA_PUBKEY、DSAparams、ECPKParameters、ECPrivateKey、EC_PUBKEY等。

3. PEM_ASN1_read/PEM_ASN1_read_bio

   比较底层的PEM读取函数，2中的函数都调用了这两个函数。

4. PEM_ASN1_write/PEM_ASN1_write_bio

   比较底层的PEM读取函数，1中的函数都调用了这两个函数。

5. PEM_read_bio

   读取PEM文件的各个部分，包括文件类型、头信息以及消息体(base64解码后的结果）。

6. PEM_get_EVP_CIPHER_INFO

   根据头信息获取对称算法，并加载初始化向量iv。

7. PEM_do_header

   根据对称算法，解密数据。

8. PEM_bytes_read_bio

   获取PEM数据，得到的结果为一个DER编码的明文数据，该函数先后调用了5、6和7函数。

## 22.4  编程示例

​	**示例1**

```cpp
#include <openssl/evp.h>
#include <openssl/pem.h>
int mycb(char* buf, int num, int a, char* key) {
    if (key)
        strcpy(buf, key);
    else {
        if (a == 1)
            printf("请输入加密密码:\n");
        else
            printf("请输入解密密码:\n");
        scanf("%s", buf);
    }
    return strlen(buf);
}
int main() {
    int ret;
    BIO *out, *in;
    RSA *r, *read;
    int i, bits = 512;
    unsigned long e = RSA_3;
    BIGNUM* bne;
    const EVP_CIPHER* enc = NULL;
    bne = BN_new();
    ret = BN_set_word(bne, e);
    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if (ret != 1) {
        printf("RSA_generate_key_ex err!\n");
        return -1;
    }
    enc = EVP_des_ede3_ofb();
    out = BIO_new_file("pri.pem", "w");
    //     ret=PEM_write_bio_RSAPrivateKey(out,r,enc,NULL,0,mycb,"123456");
    //     ret=PEM_write_bio_RSAPrivateKey(out,r,enc,NULL,0,NULL,"123456");
    ret = PEM_write_bio_RSAPrivateKey(out, r, enc, NULL, 0, mycb, NULL);
    if (ret != 1) {
        RSA_free(r);
        BIO_free(out);
        return -1;
    }
    BIO_flush(out);
    BIO_free(out);
    out = BIO_new_file("pub.pem", "w");
    ret = PEM_write_bio_RSAPublicKey(out, r);
    if (ret != 1) {
        RSA_free(r);
        BIO_free(out);
        return -1;
    }
    BIO_flush(out);
    BIO_free(out);
    OpenSSL_add_all_algorithms();
    in = BIO_new_file("pri.pem", "rb");
    read = RSA_new();
    //     read=PEM_read_bio_RSAPublicKey(in,&read,NULL,NULL);
    //     read=PEM_read_bio_RSAPrivateKey(in,&read,mycb,"123456");
    //     read=PEM_read_bio_RSAPrivateKey(in,&read,NULL,"123456");
    read = PEM_read_bio_RSAPrivateKey(in, &read, mycb, NULL);
    if (read->d != NULL)
        printf("test ok!\n");
    else
        printf("err!\n");
    RSA_free(read);
    BIO_free(in);
    return 0;
}
#include <openssl/evp.h>
#include <openssl/pem.h>
int mycb(char* buf, int num, int a, char* key) {
    if (key)
        strcpy(buf, key);
    else {
        if (a == 1)
            printf("请输入加密密码:\n");
        else
            printf("请输入解密密码:\n");
        scanf("%s", buf);
    }
    return strlen(buf);
}
int main() {
    int ret;
    BIO *out, *in;
    RSA *r, *read;
    int i, bits = 512;
    unsigned long e = RSA_3;
    BIGNUM* bne;
    const EVP_CIPHER* enc = NULL;
    bne = BN_new();
    ret = BN_set_word(bne, e);
    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if (ret != 1) {
        printf("RSA_generate_key_ex err!\n");
        return -1;
    }
    enc = EVP_des_ede3_ofb();
    out = BIO_new_file("pri.pem", "w");
    // ret=PEM_write_bio_RSAPrivateKey(out,r,enc,NULL,0,mycb,"123456");
    // ret=PEM_write_bio_RSAPrivateKey(out,r,enc,NULL,0,NULL,"123456");
    ret = PEM_write_bio_RSAPrivateKey(out, r, enc, NULL, 0, mycb, NULL);
    if (ret != 1) {
        RSA_free(r);
        BIO_free(out);
        return -1;
    }
    BIO_flush(out);
    BIO_free(out);
    out = BIO_new_file("pub.pem", "w");
    ret = PEM_write_bio_RSAPublicKey(out, r);
    if (ret != 1) {
        RSA_free(r);
        BIO_free(out);
        return -1;
    }
    BIO_flush(out);
    BIO_free(out);
    OpenSSL_add_all_algorithms();
    in = BIO_new_file("pri.pem", "rb");
    read = RSA_new();
    // read=PEM_read_bio_RSAPublicKey(in,&read,NULL,NULL);
    // read=PEM_read_bio_RSAPrivateKey(in,&read,mycb,"123456");
    // read=PEM_read_bio_RSAPrivateKey(in,&read,NULL,"123456");
    read = PEM_read_bio_RSAPrivateKey(in, &read, mycb, NULL);
    if (read->d != NULL)
        printf("test ok!\n");
    else
        printf("err!\n");
    RSA_free(read);
    BIO_free(in);
    return 0;
}

```

输出：

```log
请输入加密密码 :
123456
请输入解密密码 :
123456
test ok !
```

​	本示例生成RSA密钥，并将私钥写入成PMI格式写入文件；然后再读取。主要需要注意的是回调函数的用法。用户可以采用默认的方式，也可以自己写。采用默认方式时，回调函数设为NULL，否则设置为用户实现调回调函数地址。另外，最后一个参数如果为空，将需要用户输入口令，否则采用参数所表示的口令。

​	**示例2**

```cpp
#include <openssl/bio.h>
#include <openssl/pem.h>
int main() {
    BIO* bp;
    char *name = NULL, *header = NULL;
    unsigned char* data = NULL;
    int len, ret, ret2;
    EVP_CIPHER_INFO cipher;
    OpenSSL_add_all_algorithms();
    bp = BIO_new_file("server2.pem", "r");
    while (1) {
        ret2 = PEM_read_bio(bp, &name, &header, &data, &len);
        if (ret2 == 0)
            break;
        if (strlen(header) > 0) {
            ret = PEM_get_EVP_CIPHER_INFO(header, &cipher);
            ret = PEM_do_header(&cipher, data, &len, NULL, NULL);
            if (ret == 0) {
                printf("PEM_do_header err!\n");
                return -1;
            }
        }
        OPENSSL_free(name);
        OPENSSL_free(header);
        OPENSSL_free(data);
    }
    printf("test ok.\n");
    BIO_free(bp);
    return 0;
}
```

说明：本例server2.pem的内容如下：

```log
  —–BEGIN CERTIFICATE—–
MIIB6TCCAVICAQYwDQYJKoZIhvcNAQEEBQAwWzELMAkGA1UEBhMCQVUxEzARBgNVBAgTClF1ZWVuc2xhbmQxGjAYBgNVBAoTEUNyeXB0U29mdCBQdHkgTHRkMRswGQYDVQQDExJUZXN0IENBICgxMDI0IGJpdCkwHhcNMDAxMDE2MjIzMTAzWhcNMDMwMTE0MjIzMTAzWjBjMQswCQYDVQQGEwJBVTETMBEGA1UECBMKUXVlZW5zbGFuZDEaMBgGA1UEChMRQ3J5cHRTb2Z0IFB0eSBMdGQxIzAhBgNVBAMTGlNlcnZlciB0ZXN0IGNlcnQgKDUxMiBiaXQpMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJ+zw4Qnlf8SMVIPFe9GEcStgOY2Ww/dgNdhjeD8ckUJNP5VZkVDTGiXav6ooKXfX3j/7tdkuD8Ey2//Kv7+ue0CAwEAATANBgkqhkiG9w0BAQQFAAOBgQCT0grFQeZaqYb5EYfk20XixZV4GmyAbXMftG1Eo7qGiMhYzRwGNWxEYojf5PZkYZXvSqZ/ZXHXa4g59jK/rJNnaVGMk+xIX8mxQvlV0n5O9PIha5BX5teZnkHKgL8aKKLKW1BK7YTngsfSzzaeame5iKfzitAE+OjGF+PFKbwX8Q==
—–END CERTIFICATE—–
—–BEGIN RSA PRIVATE KEY—–
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,8FDB648C1260EDDA
CPdURB7aZqM5vgDzZoim/qtoLi5PdrrJol9LrH7CNqJfr9kZfmiexZrE4pV738HhUBoidqT8moxzDtuBP54FaVri1IJgbuTZPiNbLn00pVcodHdZrrttrjy1eWLlFmN/QcCRQhIoRow+f1AhYGhsOhVH+m4fRb8P9KXpPbEDYVcG0R0EQq6ejdmhS0vV+YXGmghBSGH12i3OfRJXC0TXvazORsT322jiVdEmajND6+DpAtmMmn6JTYm2RKwgFr9vPWv9cRQaMP1yrrBCtMiSINS4mGieN1sE1IvZLhn+/QDNfS4NxgnMfFjSl26TiNd/m29ZNoeDDXEcc6HXhoS/PiT+zPBq7t23hmAroqTVehV9YkFsgr71okOTBwlYMbFJ9goC87HYjJo4t0q9IY53GCuoI1Mont3Wm9I8QlWh2tRq5uraDlSq7U6Z8fwvC2O+wFF+PhRJrgD+4cBETSQJhj7ZVrjJ8cxCbtGcE/QiZTmmyY3sirTlUnIwpKtlfOa9pwBaoL5hKk9ZYa8L1ZCKKMoB6pZw4N9OajVkMUtLiOv3cwIdZk4OIFSSm+pSfcfUdG45a1IQGLoqvt9svckz1sOUhuu5zDPIQUYrHFn3arqUO0zCPVWPMm9oeYOkB2WCz/OiNhTFynyX0r+Hd3XeT26lgFLfnCkZlXiW/UQXqXQFSjC5sWd5XJ1+1ZgAdXq0L5qv/vAIrfryNNZHRFxC8QDDI504OA1AHDkHuH9NO9Ur8U0z7qrsUAf5OnMRUK//QV11En5o/pWcZKD0SVGS03+FVqMhtTsWKzsil5CLAfMbOWUw+/1k1A==
—–END RSA PRIVATE KEY—–
```

* PEM_read_bio函数可以循环读取文件中的内容。
* PEM_do_header用于解密数据，之前必须调用函数OpenSSL_add_all_algorithms。
* PEM_do_header解密后的数据放在data中，长度由len表示，len即是输入参数又是输出参数。
* name、header和data等用OPENSSL_free释放内存。