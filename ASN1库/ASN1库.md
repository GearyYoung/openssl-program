# 第十三章 ASN1库

## 13.1  ASN1简介

       ASN.1(Abstract Syntax Notation One，X.208)，是一套灵活的标记语言，它允许定义多种数据类型，从integer、bit string 一类的简单类型到结构化类型，如set 和sequence，并且可以使用这些类型构建复杂类型。

       DER编码是ANS.1定义的将对象描述数据编码成八位串值的编码规则，它给出了对ANS.1值（对象的类型和值）的唯一编码规则。

       在ANS.1中，一个类型是一组值，对于某些类型，值的个数是已知的，而有些类型中值的个数是不固定的。ANS.1中有四种类型：

1. 简单类型

                     BIT STRING  任意0、1位串；

                     IA5String     任意IA5(ASCII)字符串；

                     INTEGER   任意一个整数；

                     NULL      空值；

                     OBJECT IDENTIFIER        一个对象标识号（一串整数），标识算法或属性类型等对象；

                     OCTET STRING   8位串；

                     PrintableString       任意可打印字符串；

                     T61String       任意T.61（8位）字符串；

                     UTCTime       一个“协同世界时”或“格林威治标准时（G.M.T）”。

2. 结构类型

                     结构类型由组件组成，ANS.1定义了四种结构类型：

                     SEQUENCE                 一个或多个类型的有序排列；

                     SEQUENCE OF           一个给定类型的0个或多个有序排列；

                     SET                            一个或多个类型的无序集合；

                     SET OF                     一个给定类型的0个或多个无序集合。

3. 带标记类型

   ​在一个应用内部区分类型的有效方法是使用标记，标记也同样用于区分一个结构类型内部不同的组件。例如SET或SEQUENCE类型可选项通常使用上下文标记以避免混淆。有两种标记类型的方法：隐式和显式。隐式标记类型是将其它类型的标记改变，得到新的类型。隐式标记的关键字是IMPLICIT。显式标记类型是将其它类型加上一个外部标记，得到新的类型。显式标记的关键字是EXPLICIT。

为了进行编码，隐式标记类型除了标记不同以外，可以视为与其基础类型相同。显式标记类型可以视为只有一个组件的结构类型。

4. 其它类型

​        类型和值用符号::=表示，符号左边的是名字，右边是类型和值。名字又可以用于定义其它的类型和值。

​	除了CHOICE类型、ANY类型以外，所有ANS.1类型都有一个标记，标记由一个类和一个非负的标记码组成，当且仅当标记码相同时，ANS.1类型是相同的。也就是说，影响其抽象意义的不是ANS.1类型的名字，而是其标记。

​	通用标记在X.208中定义，并给出相应的通用标记码。其它的标记类型分别在很多地方定义，可以通过隐式和显式标记获得。

       下表列出了一些通用类型及其标记：

              类型                               标记码（十六进制）

              INTEGER                          02

              BIT STRING                         03

              OCTET STRING                     04

              NULL                               05

              OBJECT IDENTIFIER                       06

              SEQUENCE and SEQUENCEOF     10

              SET and SET OF                      11

              PrintableString                         13

              T61String                             14

              IA5String                             16

              UTCTime                            17

## 13.2  DER编码

​	DER给出了一种将ASN.1值表示为8位串的方法。DER编码包含三个部分：

Ø  标识（一个或多个8位串）：定义值的类和标记码，指出是原始编码还是结构化编码。

Ø  长度（一个或多个8位串）：对于定长编码，指出内容中8位串的个数；对于不定长编码，指出长度是不定的。

Ø  内容（一个或多个8位串）：对于原始定长编码，给出真实值；对于结构化编码，给出各组件BER编码的按位串联结果。

Ø  内容结束（一个或多个8位串）：对于结构化不定长编码，标识内容结束；对于其它编码，无此项。

## 13.3  ASN1基本类型示例

1）  ASN1_BOOLEAN

表明了ASN1语法中的true和flase。用户以用UltraEdit等工具编辑一个二进制文件来查看，此二进制文件的内容为：0x30 0x03 0x01 0x01 0x00，然后用asn1view工具查看此文件内容。显示如下：

[![clip_image002](http://www.pengshuo.me/wp-content/uploads/2014/04/clip_image002_thumb.jpg)](http://www.pengshuo.me/wp-content/uploads/2014/04/clip_image002.jpg)

其中0x01 (表示为BOOLEAN) 0x01(表示后面值的长度) 0x00（值）为本例BOOLEAN的DER编码。

       2）  ASN1_OBJECT

ASN1中的OBJECT表明来一个对象，每个对象有一个OID(object id)。例如：OU的OID为2.5.4.11。OBJECT对象在DER编码的时候通过计算将OID转换为另外一组数据(可用函数a2d_ASN1_OBJECTH函数)。用户编辑一个二进制文件，内容为：0x30 0x05 0x06 0x03 0x55 0x04 0x0A，用asn1view打开查看。如下：

[![clip_image004](http://www.pengshuo.me/wp-content/uploads/2014/04/clip_image004_thumb.jpg)](http://www.pengshuo.me/wp-content/uploads/2014/04/clip_image004.jpg)

其中0x06（表示为OBJECT类型） 0x03（值的长度） 0x55 0x04 0x0A（此三项由2.5.4.11计算而来）为此OBJECT的DER编码。

       3)    ASN1_INTEGER

ASN1中的INTEGER类型用于表示整数。编辑一个二进制文件，其内容为：0x30 0x03 0x02（整数） 0x01 （整数值长度）0x55 (整数值)。用an1view查看如下：

[![clip_image006](http://www.pengshuo.me/wp-content/uploads/2014/04/clip_image006_thumb.jpg)](http://www.pengshuo.me/wp-content/uploads/2014/04/clip_image006.jpg)

4）  ASN1_ENUMERATED

ASN1枚举类型，示例如下：

[![clip_image008](http://www.pengshuo.me/wp-content/uploads/2014/04/clip_image008_thumb.jpg)](http://www.pengshuo.me/wp-content/uploads/2014/04/clip_image008.jpg)

5)           ASN1_BIT_STRING

示例如下：

[![clip_image010](http://www.pengshuo.me/wp-content/uploads/2014/04/clip_image010_thumb.jpg)](http://www.pengshuo.me/wp-content/uploads/2014/04/clip_image010.jpg)

此图显示0x01 0x02的DER编码：0x03（BIT STRING 类型） 0x02（长度） 0x01 0x02（比特值）。

6）  ASN1_OCTET_STRING

如下：

[![clip_image012](http://www.pengshuo.me/wp-content/uploads/2014/04/clip_image012_thumb.jpg)](http://www.pengshuo.me/wp-content/uploads/2014/04/clip_image012.jpg)

显示0x01 0x02的OCTET STRING编码：0x04(OCTET STRING) 0x02(长度) 0x01 0x02（值）。

7）ASN1_PRINTABLESTRING

可打印字符，如下：

[![clip_image014](http://www.pengshuo.me/wp-content/uploads/2014/04/clip_image014_thumb.jpg)](http://www.pengshuo.me/wp-content/uploads/2014/04/clip_image014.jpg)

显示来可打印字符“asn1“的DER编码，其编码值为0x13(PRINTABLESTRING) 0x04(值长度) 0x61 0x73 0x6E 0x31(值，即“asn1”)。

       其他：

ASN1_UTCTIME：表示时间。

ASN1_GENERALIZEDTIME：表示时间。

ASN1_VISIBLESTRING：存放可见字符。

ASN1_UTF8STRING：用于存放utf8字符串，存放汉字需要将汉字转换为utf8字符串。

ASN1_TYPE：用于存放任意类型。

## 13.4  openssl 的ASN.1库

       Openssl的ASN.1库定义了asn.1对应的基本数据结构和大量用于DER编码的宏。比如整型定义如下：

       typedef struct asn1_string_st ASN1_INTEGER;

       另外，还用相同的数据结构asn1_string_st定义了：

       ASN1_ENUMERATED；

       ASN1_BIT_STRING；

       ASN1_OCTET_STRING；

       ASN1_PRINTABLESTRING；

       ASN1_T61STRING；

       ASN1_IA5STRING；

       ASN1_GENERALSTRING；

       ASN1_UNIVERSALSTRING；

       ASN1_BMPSTRING；

       ASN1_UTCTIME；

       ASN1_TIME；

       ASN1_GENERALIZEDTIME；

       ASN1_VISIBLESTRING；

       ASN1_UTF8STRING；

       ASN1_TYPE;

       这些都是定义基本数据结构的必要元素。

对于每种类型，均有四种最基本的函数：new、free、i2d和d2i。其中new函数用于生成一个新的数据结构；free用于释放该结构；       i2d用于将该内部数据结构转换成DER编码；d2i用于将DER编码转换成内部数据结构。另外，大部分类型都有set和get函数，用于给内部数据结构赋值和从中取值。以ASN1_INTEGER为例，它有如下基本函数：

              ASN1_INTEGER ASN1_INTEGER_new(void);

              void*ASN1_INTEGER_free(ASN1_INTEGER *a);

              ASN1_INTEGER   *d2i_ASN1_INTEGER(ASN1_INTEGER **a,

unsigned char **in,long len);

              int   i2d_ASN1_INTEGER(ASN1_INTEGER *a,unsigned char **out);

              long ASN1_INTEGER_get(ASN1_INTEGER *a)

              int ASN1_INTEGER_set(ASN1_INTEGER *a, long v)；

              前面的四个函数由DECLARE_ASN1_FUNCTIONS(ASN1_INTEGER)声明，并由          IMPLEMENT_ASN1_FUNCTIONS(ASN1_INTEGER)实现。

              采用ASN.1定义的复杂的结构都是由基本的类型构造的，因此可以用这些基本的数据来实现对复杂结构的编码。

## 13.5  用openssl的ASN.1库DER编解码

       当采用Openssl的ASN.1库编码一个asn.1定义的结构的时候，需要采用如下步骤：

1. 用 ASN.1语法定义内部数据结构，并声明函数；

   所谓内部数据结构，指的是Openssl中用基本的数据类型按照ASN.1语法定义的其他的数据结构，这种数据结构可以方便的用于编解码。

   以x509v4中的证书有效期为例，证书有效期定义如下：

```cpp
AttCertValidityPeriod:: = SEQUENCE {
    notBeforeTime GeneralizedTime,
    notAfterTime GeneralizedTime
}
```

​	所以我们可以定义相应的内部数据结构，如下：

```cpp
typedef struct X509V4_VALID_st {
    ASN1_GENERALIZEDTIME* notBefore;
    ASN1_GENERALIZEDTIME* notAfter;
} X509V4_VALID;
DECLARE_ASN1_FUNCTIONS(X509V4_VALID)
```

​	其中最后一行用于定义四个函数：

```cpp
X509V4_VALID* X509V4_VALID_new(void);
void* X509V4_VALID_free(X509V4_VALID* a);
X509V4_VALID* d2i_ASN1_INTEGER(X509V4_VALID** a, unsigned char** in, long len);
int i2d_ X509V4_VALID(X509V4_VALID* a, unsigned char** out);
```

2. 实现内部数据结构的四个基本函数

   实现内部数据结构的基本函数，是通过一系列的宏来实现的。定义的模式如下，以属性证书有效期为例，如下：

```cpp
/* X509V4_VALID */
ASN1_SEQUENCE(X509V4_VALID) = {
ASN1_SIMPLE(X509V4_VALID, notBefore, ASN1_GENERALIZEDTIME),
ASN1_SIMPLE(X509V4_VALID, notAfter,ASN1_GENERALIZEDTIME)
} ASN1_SEQUENCE_END(X509V4_VALID)
IMPLEMENT_ASN1_FUNCTIONS(X509V4_VALID)

```

​	这样通过宏就实现了一个asn .1定义结构的最基本的四个函数。本例有五个宏，采用什么样的宏，与数据结构的asn .1定义相关。

## 13.6  Openssl的ASN.1宏

Openssl中的ASN.1宏用来定义某种内部数据结构以及这种结构如何编码，部分宏定义说明如下：

1. DECLARE_ASN1_FUNCTIONS

   用于声明一个内部数据结构的四个基本函数，一般可以在头文件中定义。

2. IMPLEMENT_ASN1_FUNCTIONS

    用于实现一个数据结构的四个基本函数。

3. ASN1_SEQUENCE

   用于SEQUENCE，表明下面的编码是一个SEQUENCE。

4. ASN1_CHOICE

   表明下面的编码是选择其中一项，为CHOICE类型。

5. ASN1_SIMPLE

   用于简单类型或结构类型，并且是必须项。

6. ASN1_OPT

   用于可选项，表明asn.1语法中，本项是可选的。

7. ASN1_EXP_OPT

   用于显示标记，表明asn.1语法中，本项是显示类型，并且是可选的；

8. ASN1_EXP

   用于显示标记，表明asn.1语法中，本项是显示标记。

9. ASN1_IMP_SEQUENCE_OF_OPT

   用于隐示标记，表明asn.1语法中，本项是一个SEQUENCE序列，为隐示类型，并且是可选的。

10. ASN1_IMP_OPT

   用于隐示标记，表明asn.1语法中，本项是隐示类型，并且是可选的。

11. ASN1_IMP

   用于隐示标记，表明asn.1语法中，本项是隐示类型。

12. ASN1_SEQUENCE_END

   用于SEQUENCE结束。

13. ASN1_CHOICE_END

   用于结束CHOICE类型。

## 13.7  ASN1常用函数

       ASN1的基本的数据类型一般都有如下函数：new、free、i2d、d2i、i2a、a2i、print、set、get、cmp和dup。其中new、free、i2d、d2i函数通过宏定义实现。new函数用于分配空间，生成ASN1数据结构;free用于释放空间；i2d函数将ASN1数据结构转换为DER编码；d2i将DER编码转换为ASN1数据结构，i2a将内部结构转换为ASCII码，a2i将ASCII码转换为内部数据结构。set函数用于设置ASN1类型的值，get函数用于获取ASN1类型值；print将ASN1类型打印；cmp用于比较ASN1数据结构；dup函数进行数据结构的拷贝。

       常用的函数有：

1. int a2d_ASN1_OBJECT(unsigned char *out, int olen, const char *buf, int num)

       计算OID的DER编码，比如将2.99999.3形式转换为内存形式。示例：

```cpp
#include <openssl/asn1.h>
void main() {
    const char oid[] = {"2.99999.3"};
    int i;
    unsigned char* buf;
    i = a2d_ASN1_OBJECT(NULL, 0, oid, -1);
    if (i <= 0)
        return;
    buf = (unsigned char*)malloc(sizeof(unsigned char) * i);
    i = a2d_ASN1_OBJECT(buf, i, oid, -1); // 86 8D 6F 03
    free(buf);
    return;
}
```

2. int a2i_ASN1_INTEGER(BIO *bp,ASN1_INTEGER *bs,char *buf,int size)

   将bp中的ASC码转换为ASN1_INTEGER,buf存放BIO中的ASC码。示例如下：

```cpp
#include <openssl/asn1.h>
int main() {
    BIO* bp;
    ASN1_INTEGER* i;
    unsigned char buf[50];
    int size, len;
    bp = BIO_new(BIO_s_mem());
    len = BIO_write(bp, "0FAB08BBDDEECC", 14);
    size = 50;
    i = ASN1_INTEGER_new();
    a2i_ASN1_INTEGER(bp, i, buf, size);
    BIO_free(bp);
    ASN1_INTEGER_free(i);
    return 0;
}
```

3. int a2i_ASN1_STRING(BIO *bp,ASN1_STRING *bs,char *buf,int size)

   将ASCII码转换为ASN1_STRING，示例：

```cpp
#include <openssl/asn1.h>
int main() {
    BIO* bp;
    ASN1_STRING* str;
    unsigned char buf[50];
    int size, len;
    bp = BIO_new(BIO_s_mem());
    len = BIO_write(bp, "B2E2CAD4", 8);
    size = 50;
    str = ASN1_STRING_new();
    a2i_ASN1_STRING(bp, str, buf, size);
    BIO_free(bp);
    ASN1_STRING_free(str);
    return 0;
}
```

​	转换后str->data的前四个字节即变成“测试“。

4. unsigned char *asc2uni(const char *asc, int asclen, unsigned char **uni, int *unilen) 将ASCII码转换为unicode，示例：

```cpp
#include <openssl/crypto.h>
#include <stdio.h>
int main() {
    unsigned char asc[50] = {"B2E2CAD4"};
    unsigned char uni[50], *p, *q;
    int ascLen, unlen;
    ascLen = strlen(asc);
    q = asc2uni(asc, ascLen, NULL, &unlen);
    OPENSSL_free(q);
    return 0;
}
```

5. int ASN1_BIT_STRING_get_bit(ASN1_BIT_STRING *a, int n)

   本函数根据n获取其比特位上的值，示例：

```cpp
#include <openssl/asn1.h>
int main() {
    int ret, i, n;
    ASN1_BIT_STRING* a;
    a = ASN1_BIT_STRING_new();
    ASN1_BIT_STRING_set(a, "ab", 2);
    for (i = 0; i < 2 * 8; i++) {
        ret = ASN1_BIT_STRING_get_bit(a, i);
        printf("%d", ret); // 0110000101100010
    }
    ASN1_BIT_STRING_free(a);
    return 0;
}
```

6. ASN1_BIT_STRING_set

   设置ASN1_BIT_STRING的值，它调用了ASN1_STRING_set函数；

7. void *ASN1_d2i_bio(void *(*xnew)(void), d2i_of_void *d2i, BIO *in, void **x)

   对bio的数据DER解码，xnew无意义，d2i为DER解码函数，in为bio数据，x为数据类型，返回值为解码后的结果。如果x分配了内存，x所指向的地址与返回值一致。示例如下：

```cpp
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/x509v3.h>
#include <stdio.h>
int main() {
    BIO* in;
    X509 **out = NULL, *x;
    in = BIO_new_file("a.cer", "r");
    out = (X509**)malloc(sizeof(X509*));
    *out = NULL;
    x = ASN1_d2i_bio(NULL, (d2i_of_void*)d2i_X509, in, out);
    X509_free(x);
    free(out);
    return 0;
}
```

8. void *ASN1_d2i_fp(void *(*xnew)(void), d2i_of_void *d2i, FILE *in, void **x)

   将in指向的文件进行DER解码，其内部调用了ASN1_d2i_bi函数，用法与ASN1_d2i_bi类似。

9. int ASN1_digest(i2d_of_void *i2d, const EVP_MD *type, char *data,unsigned char *md, unsigned int *len)

   ASN1数据类型签名。将data指针指向的ASN1数据类型用i2d函数进行DER编码，然后用type指定的摘要方法进行计算，结果存放在md中，结果的长度由len表示。

10. int ASN1_i2d_bio(i2d_of_void *i2d, BIO *out, unsigned char *x)

   将ASN1数据结构DER编码，并将结果写入bio。示例如下：

```cpp
#include <openssl/asn1.h>
#include <openssl/bio.h>
int main() {
    int ret;
    BIO* out;
    ASN1_INTEGER* a;
    out = BIO_new_file("int.cer", "w");
    a = ASN1_INTEGER_new();
    ASN1_INTEGER_set(a, (long)100);
    ret = ASN1_i2d_bio(i2d_ASN1_INTEGER, out, a);
    BIO_free(out);
    return 0;
}
```

​	本程序将ASN1_INTEGER类型装换为DER编码并写入文件。int.cer的内容如下：02 01 64  （十六进制）。

11.  int ASN1_i2d_fp(i2d_of_void *i2d, FILE *out, void *x)

    将ASN1数据结构DER编码并写入FILE，此函数调用了ASN1_i2d_bio。

12.  void *ASN1_dup(i2d_of_void *i2d, d2i_of_void *d2i, char *x)

    ASN1数据复制。x为ASN1内部数据结构，本函数先将x通过i2d将它变成DER编码，然后用d2i再DER解码，并返回解码结果。

13.  ASN1_ENUMERATED_set

    设置ASN1_ENUMERATED的值。

14.  ASN1_ENUMERATED_get

    获取ASN1_ENUMERATED的值；示例如下：

```cpp
#include <openssl/asn1.h>
int main() {
    long ret;
    ASN1_ENUMERATED* a;
    a = ASN1_ENUMERATED_new();
    ASN1_ENUMERATED_set(a, (long)155);
    ret = ASN1_ENUMERATED_get(a);
    printf("%ld\n", ret);
    return 0;
}
```

15.  BIGNUM *ASN1_ENUMERATED_to_BN(ASN1_ENUMERATED *ai, BIGNUM *bn)

    将ASN1_ENUMERATED类型转换为BN大数类型。此函数调用BN_bin2bn函数获取bn，如果ai->type表明它是负数，再调用BN_set_negative设置bn成负数。示例如下：

```cpp
#include <openssl/asn1.h>
int main() {
    long ret;
    ASN1_ENUMERATED* a;
    BIGNUM* bn;
    a = ASN1_ENUMERATED_new();
    ASN1_ENUMERATED_set(a, (long)155);
    ret = ASN1_ENUMERATED_get(a);
    bn = BN_new();
    bn = ASN1_ENUMERATED_to_BN(a, bn);
    BN_free(bn);
    ASN1_ENUMERATED_free(a);
    return 0;
}
```

​	如果ASN1_ENUMERATED_to_BN的第二个参数为NULL,bn将在内部分配空间。

16.  int ASN1_GENERALIZEDTIME_check(ASN1_GENERALIZEDTIME *a)

    检查输入参数是不是合法的ASN1_GENERALIZEDTIME类型。

17.  int ASN1_parse_dump(BIO *bp, const unsigned char *pp, long len, int indent, int dump)

    本函数用于将pp和len指明的DER编码值写在BIO中，其中indent和dump用于设置打印的格式。indent用来设置打印出来当列之间空格个数，ident越小，打印内容越紧凑。dump表明当asn1单元为BIT STRING或OCTET STRING时，打印内容的字节数。示例如下：

```cpp
#include <openssl/asn1.h>
#include <openssl/bio.h>
int main() {
    int ret, len, indent, dump;
    BIO* bp;
    char *pp, buf[5000];
    FILE* fp;
    bp = BIO_new(BIO_s_file());
    BIO_set_fp(bp, stdout, BIO_NOCLOSE);
    fp = fopen("der.cer", "rb");
    len = fread(buf, 1, 5000, fp);
    fclose(fp);
    pp = buf;
    indent = 7;
    dump = 11;
    ret = ASN1_parse_dump(bp, pp, len, indent, dump);
    BIO_free(bp);
    return 0;
}
```

​	其中der.cer为一个DER编码的文件，比如一个数字证书。

18.  int ASN1_sign(i2d_of_void *i2d, X509_ALGOR *algor1, X509_ALGOR *algor2,       ASN1_BIT_STRING *signature, char *data, EVP_PKEY *pkey, const EVP_MD *type)

    对ASN1数据类型签名。i2d为ASN1数据的DER方法，signature用于存放签名结果，data为ASN1数据指针，pkey指明签名密钥，type为摘要算法，algor1和algor2无用，可全为NULL。签名时，先将ASN1数据DER编码，然后摘要，最后签名运算。

    ​在x509.h中有很多ASN1数据类型的签名都通过此函数来定义，有X509_sign、X509_REQ_sign、X509_CRL_sign、NETSCAPE_SPKI_sign等。示例如下：

```cpp
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
int main() {
    int ret;
    ASN1_INTEGER* a;
    EVP_MD* md;
    EVP_PKEY* pkey;
    char* data;
    ASN1_BIT_STRING* signature = NULL;
    RSA* r;
    int i, bits = 1024;
    unsigned longe = RSA_3;
    BIGNUM* bne;
    bne = BN_new();
    ret = BN_set_word(bne, e);
    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if (ret != 1) {
        printf("RSA_generate_key_ex err!\n");
        return -1;
    }
    pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, r);
    a = ASN1_INTEGER_new();
    ASN1_INTEGER_set(a, 100);
    md = EVP_md5();
    data = (char*)a;
    signature = ASN1_BIT_STRING_new();
    ret = ASN1_sign(i2d_ASN1_INTEGER, NULL, NULL, signature, data, pkey, md);
    printf("signature len : %d\n", ret);
    EVP_PKEY_free(pkey);
    ASN1_INTEGER_free(a);
    free(signature);
    return 0;
}
```

​	本例将ASN1_INTEGER整数签名。

19.  ASN1_STRING *ASN1_STRING_dup(ASN1_STRING *str)

    ASN1_STRING类型拷贝。内部申请空间，需要用户调用ASN1_STRING_free释放该空间。

20.  int ASN1_STRING_cmp(ASN1_STRING *a, ASN1_STRING *b)

    ASN1_STRING比较。ossl_typ.h中绝大多数ASN1基本类型都定义为ASN1_STRING，所以，此函数比较通用。示例如下：

```cpp
#include <openssl/asn1.h>
int main() {
    int ret;
    ASN1_STRING *a, *b, *c;
    a = ASN1_STRING_new();
    b = ASN1_STRING_new();
    ASN1_STRING_set(a, "abc", 3);
    ASN1_STRING_set(b, "def", 3);
    ret = ASN1_STRING_cmp(a, b);
    printf("%d\n", ret);
    c = ASN1_STRING_dup(a);
    ret = ASN1_STRING_cmp(a, c);
    printf("%d\n", ret);
    ASN1_STRING_free(a);
    ASN1_STRING_free(b);
    ASN1_STRING_free(c);
    return 0;
}
```

21.  unsigned char * ASN1_STRING_data(ASN1_STRING *x)

    获取ASN1_STRING数据存放地址，即ASN1_STRING数据结构中data地址。本函数由宏实现。

22.  int ASN1_STRING_set(ASN1_STRING *str, const void *_data, int len)

    设置ASN1字符串类型的值。str为ASN1_STRING地址，_data为设置值的首地址，len为被设置值的长度。示例如下：

```cpp
ASN1_STRING     *str=NULL;
str=ASN1_STRING_new();
ASN1_STRING_set(str,”abc”,3);
```

​	此示例生成的ASN1_STRING类型为OCTET_STRING。其他的ASN1_STRING类型也能用此函数设置，如下：

```cpp
ASN1_PRINTABLESTRING       *str=NULL;
str=ASN1_PRINTABLESTRING_new();
ASN1_STRING_set(str,”abc”,3);
```

23.  ASN1_STRING_TABLE *ASN1_STRING_TABLE_get(int nid)

    根据nid来查找ASN1_STRING_TABLE表。此函数先查找标准表tbl_standard，再查找扩展表stable。ASN1_STRING_TABLE数据结构在asn1.h中定义，它用于约束ASN1_STRING_set_by_NID函数生成的ASN1_STRING类型。

```cpp
typedef struct asn1_string_table_st {
    int nid;
    long minsize;
    long maxsize;
    unsigned long mask;
    unsigned long flags;
} ASN1_STRING_TABLE;
```

​	其中nid表示对象id，minsize表示此nid值的最小长度，maxsize表示此nid值的最大长度，mask为此nid可以采用的ASN1_STRING类型：B_ASN1_BMPSTRING、B_ASN1_UTF8STRING、B_ASN1_T61STRING和B_ASN1_UTF8STRING，flags用于标记是否为扩展或是否已有mask。

24.  ASN1_STRING *ASN1_STRING_set_by_NID(ASN1_STRING **out, const unsigned char *in,   int inlen, int inform, int nid)

    根据nid和输入值获取对应的ASN1_STIRNG类型。out为输出，in为输入数据，inlen为其长度，inform为输入数据的类型，可以的值有：`MBSTRING_BMP、MBSTRING_UNIV、MBSTRING_UTF8、MBSTRING_ASC，nid`为数字证书中常用的nid，在a_strnid.c中由全局变量tbl_standard定义，可以的值有：NID_commonName、NID_countryName、NID_localityName、NID_stateOrProvinceName、NID_organizationName、NID_organizationalUnitName、NID_pkcs9_emailAddress、NID_pkcs9_unstructuredName、NID_pkcs9_challengePassword、NID_pkcs9_unstructuredAddress、NID_givenName、NID_surname、NID_initials、NID_serialNumber、NID_friendlyName、NID_name、NID_dnQualifier、NID_domainComponent和NID_ms_csp_name。生成的ASN1_STRING类型可以为：ASN1_T61STRING、ASN1_IA5STRING、ASN1_PRINTABLESTRING、ASN1_BMPSTRING、ASN1_UNIVERSALSTRING和ASN1_UTF8STRING。

**示例1**

```cpp
#include <openssl/asn1.h>
#include <openssl/obj_mac.h>
#include <stdio.h>
int main() {
    int inlen, nid, inform, len;
    charin[100], out[100], *p;
    ASN1_STRING* a;
    FILE* fp;
    /* 汉字“赵”的UTF8值,可以用UltraEdit获取*/
    memset(&in[0], 0xEF, 1);
    memset(&in[1], 0xBB, 1);
    memset(&in[2], 0xBF, 1);
    memset(&in[3], 0xE8, 1);
    memset(&in[4], 0xB5, 1);
    memset(&in[5], 0xB5, 1);
    inlen = 6;
    inform = MBSTRING_UTF8;
    nid = NID_commonName;

    /* 如果调用下面两个函数，生成的ASN1_STRING类型将是ASN1_UTF8而不是ASN1_BMPSTRING    */
    ASN1_STRING_set_default_mask(B_ASN1_UTF8STRING);
    ret = ASN1_STRING_set_default_mask_asc("utf8only");
    if (ret != 1) {
        printf("ASN1_STRING_set_default_mask_asc err.\n");
        return 0;
    }
    a = ASN1_STRING_set_by_NID(NULL, in, inlen, inform, nid);
    p = out;
    len = i2d_ASN1_BMPSTRING(a, &p);
    fp = fopen("a.cer", "w");
    fwrite(out, 1, len, fp);
    fclose(fp);
    ASN1_STRING_free(a);
    return 0;
}
```

​	本例根据UTF8编码的汉字获取nid为NID_commonName的ASN1_STRING类型，其结果是一个ASN1_BMPSTRING类型。

**示例2**

```cpp
#include <openssl/asn1.h>
#include <openssl/obj_mac.h>
#include <stdio.h>
int main() {
    int inlen, nid, inform, len;
    charin[100], out[100], *p;
    ASN1_STRING* a;
    FILE* fp;
    strcpy(in, "ab");
    inlen = 2;
    inform = MBSTRING_ASC;
    nid = NID_commonName;
    /* 设置生成的ASN1_STRING类型 */
    ASN1_STRING_set_default_mask(B_ASN1_UTF8STRING);
    a = ASN1_STRING_set_by_NID(NULL, in, inlen, inform, nid);
    switch (a->type) {
    caseV_ASN1_T61STRING:
        printf("V_ASN1_T61STRING\n");
        break;
    caseV_ASN1_IA5STRING:
        printf("V_ASN1_IA5STRING\n");
        break;
    caseV_ASN1_PRINTABLESTRING:
        printf("V_ASN1_PRINTABLESTRING\n");
        break;
    caseV_ASN1_BMPSTRING:
        printf("V_ASN1_BMPSTRING\n");
        break;
    caseV_ASN1_UNIVERSALSTRING:
        printf("V_ASN1_UNIVERSALSTRING\n");
        break;
    caseV_ASN1_UTF8STRING:
        printf("V_ASN1_UTF8STRING\n");
        break;
    default:
        printf("err");
        break;
    }
    p = out;
    len = i2d_ASN1_bytes(a, &p, a->type, V_ASN1_UNIVERSAL);
    fp = fopen("a.cer", "w");
    fwrite(out, 1, len, fp);
    fclose(fp);
    ASN1_STRING_free(a);
    getchar();
    return 0;
}
```

25.  void ASN1_STRING_set_default_mask(unsigned long mask)

    设置ASN1_STRING_set_by_NID函数返回的ASN1_STRING类型。mask可以取如下值：B_ASN1_BMPSTRING、B_ASN1_UTF8STRING、B_ASN1_T61STRING和B_ASN1_UTF8STRING。

26.  int ASN1_STRING_set_default_mask_asc(char *p)

    设置ASN1_STRING_set_by_NID函数返回的ASN1_STRING类型。字符串p可以的值有：nombstr、pkix、utf8only和default，如果设置为default，则相当于没有调用本函数。

27.  int ASN1_STRING_TABLE_add(int nid, long minsize, long maxsize, unsigned long mask, unsigned long flags)

    添加扩展的ASN1_STRING_TABLE项。说明：a_strnid.c中定义了基本的ASN1_STRING_TABLE项，如果用户要添加新的ASN1_STRING_TABLE项，需要调此次函数。Openssl源代码中有好几处都有这种用法，Openssl定义标准的某种表，并且提供扩展函数供用户去扩充。

    示例：`ASN1_STRING_TABLE_add（NID_yourNID,1,100, DIRSTRING_TYPE,0）`。

28.  void ASN1_STRING_TABLE_cleanup(void)

    清除用户自建的扩展ASN1_STRING_TABLE表。

29.  int i2a_ASN1_INTEGER(BIO *bp, ASN1_INTEGER *a)

    将整数转换成为ASCII码,放在BIO中。示例如下：

```cpp
#include <openssl/asn1.h>
int main() {
    ASN1_INTEGER* i;
    long v;
    BIO* bp;
    printf("输入v的值:\n");
    scanf("%ld", &v);
    i = ASN1_INTEGER_new();
    ASN1_INTEGER_set(i, v);
    bp = BIO_new(BIO_s_file());
    BIO_set_fp(bp, stdout, BIO_NOCLOSE);
    i2a_ASN1_INTEGER(bp, i);
    BIO_free(bp);
    ASN1_INTEGER_free(i);
    printf("\n");
    return 0;
}
```

30.  int i2a_ASN1_STRING(BIO *bp, ASN1_STRING *a, int type)

    type不起作用，将ASN1_STRING转换为ASCII码.。示例如下：

```cpp
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
int main() {
    ASN1_STRING* a;
    BIO* bp;
    a = ASN1_STRING_new();
    ASN1_STRING_set(a, "测试", 4);
    bp = BIO_new(BIO_s_file());
    BIO_set_fp(bp, stdout, BIO_NOCLOSE);
    i2a_ASN1_STRING(bp, a, 1);
    BIO_free(bp);
    ASN1_STRING_free(a);
    printf("\n");
    return 0;
}
```

31.  OBJ_bsearch

    用于从排序好的数据结构地址数组中用二分法查找数据。示例如下：

```cpp
#include <openssl/objects.h>
typedef struct Student_st { int age; } Student;
int cmp_func(const void* a, const void* b) {
    Student *x, *y;
    x = *(Student**)a;
    y = *(Student**)b;
    return x->age - y->age;
}
int main() {
    int ret, num, size;
    ASN1_OBJECT* obj = NULL;
    char **addr, *p;
    Student a[6], **sort, **x;
    a[0].age = 3;
    a[1].age = 56;
    a[2].age = 5;
    a[3].age = 1;
    a[4].age = 3;
    a[5].age = 6;
    sort = (Student**)malloc(6 * sizeof(Student*));
    sort[0] = &a[0];
    sort[1] = &a[1];
    sort[2] = &a[2];
    sort[3] = &a[3];
    sort[4] = &a[4];
    sort[5] = &a[5];
    qsort(sort, 6, sizeof(Student*), cmp_func);
    obj = OBJ_nid2obj(NID_rsa);
    ret = OBJ_add_object(obj);
    if (ret == NID_undef) {
        printf("err");
    } else {
        printf("ok\n");
    }
    p = &a[4];
    addr = OBJ_bsearch(&p, (char*)sort, 6, sizeof(Student*), cmp_func);
    x = (Student**)addr;
    printf("%d == %d\n", a[4].age, (*x)->age);
    return 0;
}
```

32.  OBJ_create

    根据oid以及名称信息生成一个内部的object，示例：

```cpp
nid=OBJ_create(“1.2.3.44″,”testSn”,”testLn”)。
```

33.  OBJ_NAME_add

    OBJ_NAME_cleanup

    OBJ_NAME_get

    OBJ_NAME_init

    OBJ_NAME_remove

    OBJ_NAME_new_index

    OBJ_NAME_do_all

    OBJ_NAME_do_all_sorted

    OBJ_NAME函数用于根据名字获取对称算法或者摘要算法，主要涉及到函数有:

```cpp
int EVP_add_cipher(const EVP_CIPHER *c);
int EVP_add_digest(const EVP_MD *md);
const EVP_CIPHER *EVP_get_cipherbyname(const char *name);
const EVP_MD *EVP_get_digestbyname(const char *name);
void EVP_cleanup(void);
```

​	这些函数在evp/names.c中实现，他们调用了OBJ_NAME函数。

​	EVP_add_cipher和EVP_add_digest函数调用OBJ_NAME_init和OBJ_NAME_add函数，将EVP_CIPHER和EVP_MD信息放入哈希表，EVP_get_cipherbyname和EVP_get_digestbyname函数调用OBJ_NAME_get函数从哈希表中查询需要的信息，EVP_cleanup函数清除存放到EVP_CIPHER和EVP_MD信息。另外，程序可以通过调用OpenSSL_add_all_ciphers和OpenSSL_add_all_digests函数将所有的对称算法和摘要算法放入哈希表。

34.  int  OBJ_new_nid(int num)

    此函数将内部的new_nid加num，返回原nid。

35.  const char *OBJ_nid2ln(int n)

    根据nide得到对象的描诉。

36.  OBJ_nid2obj

       根据nid得到对象。

37.  const char *OBJ_nid2sn(int n)

    根据nid得到对象的sn(简称)。

38.  int OBJ_obj2nid(const ASN1_OBJECT *a)

    根据对象获取其nid；

39.  OBJ_obj2txt

    根据对象获取对象说明或者nid，示例：

```cpp
#include <openssl/asn1.h>
int main() {
    charbuf[100];
    int buf_len = 100;
    ASN1_OBJECT* a;
    a = OBJ_nid2obj(65);
    OBJ_obj2txt(buf, buf_len, a, 0);
    printf("%s\n", buf); // sha1WithRSAEncryption
    OBJ_obj2txt(buf, buf_len, a, 1);
    printf("%s\n", buf); // 1.2.840.113549.1.1.5
    return 0;
}
```

40.  int OBJ_sn2nid(const char *s)

    根据对象别名称获取nid

41.  OBJ_txt2nid

    根据sn或者ln获取对象的nid。

42.  OBJ_txt2obj

    根据sn或者ln得到对象。

## 13.8  属性证书编码

​	对属性证书（x509v4）编码，以下是采用Openssl的asn.1库对属性证书编/解码的源代码：

```cpp
/* x509v4.h */
/* valid time */
typedef struct X509V4_VALID_st {
    ASN1_GENERALIZEDTIME* notBefore;
    ASN1_GENERALIZEDTIME* notAfter;
} X509V4_VALID;
DECLARE_ASN1_FUNCTIONS(X509V4_VALID)
/* issuer */
typedef struct ISSUERSERIAL_st {
    GENERAL_NAMES* issuer;
    ASN1_INTEGER* subjectSN;
    ASN1_BIT_STRING* issuerUID;
} ISSUERSERIAL;
DECLARE_ASN1_FUNCTIONS(ISSUERSERIAL)
/* objdigest */
typedef struct OBJDIGEST_st {
    ASN1_ENUMERATED* digestType;
    ASN1_OBJECT* otherType;
    X509_ALGOR* digestAlg;
    ASN1_BIT_STRING* digestBit;
} OBJDIGEST;
DECLARE_ASN1_FUNCTIONS(OBJDIGEST)
/* holder */
typedef struct ACHOLDER_st {
    ISSUERSERIAL* baseCertificateID;
    GENERAL_NAMES* entityName;
    OBJDIGEST* objDigest;
} ACHOLDER;
DECLARE_ASN1_FUNCTIONS(ACHOLDER)
/* version 2 form */
typedef struct V2FORM_st {
    GENERAL_NAMES* entityName;
    ISSUERSERIAL* baseCertificateID;
    OBJDIGEST* objDigest;
} V2FORM;
DECLARE_ASN1_FUNCTIONS(V2FORM)
typedef struct ACISSUER_st {
    int type;
    union {
        V2FORM* v2Form;
    } form;
} ACISSUER;
DECLARE_ASN1_FUNCTIONS(ACISSUER)
/* X509V4_CINF */
typedef struct X509V4_CINF_st {
    ASN1_INTEGER* version;
    ACHOLDER* holder;
    ACISSUER* issuer;
    X509_ALGOR* signature;
    ASN1_INTEGER* serialNumber;
    X509V4_VALID* valid;
    STACK_OF(X509_ATTRIBUTE) * attributes;
    ASN1_BIT_STRING* issuerUID;
            STACK_OF(X509_EXTENSION*extensions;
} X509V4_CINF;
DECLARE_ASN1_FUNCTIONS(X509V4_CINF)
/* x509v4 */
typedef struct X509V4_st {
    X509V4_CINF* cert_info;
    X509_ALGOR* sig_alg;
    ASN1_BIT_STRING* signature;
} X509V4;
DECLARE_ASN1_FUNCTIONS(X509V4)
/* x509v4.c */
/* ACISSUER */
ASN1_CHOICE(ACISSUER) = {ASN1_IMP(ACISSUER, form.v2Form, V2FORM, 0)} ASN1_CHOICE_END(ACISSUER)
    IMPLEMENT_ASN1_FUNCTIONS(ACISSUER)
    /* ACHOLDER */
    ASN1_SEQUENCE(ACHOLDER) = {ASN1_IMP_OPT(ACHOLDER, baseCertificateID, ISSUERSERIAL, 0),
                               ASN1_IMP_SEQUENCE_OF_OPT(ACHOLDER, entityName, GENERAL_NAME, 1),
                               ASN1_IMP_OPT(ACHOLDER, objDigest, OBJDIGEST,
                                            2)} ASN1_SEQUENCE_END(ACHOLDER)
        IMPLEMENT_ASN1_FUNCTIONS(ACHOLDER)
    /* V2FORM */
    ASN1_SEQUENCE(V2FORM) = {ASN1_SEQUENCE_OF_OPT(V2FORM, entityName, GENERAL_NAME),
                             ASN1_IMP_OPT(V2FORM, baseCertificateID, ISSUERSERIAL, 0),
                             ASN1_IMP_OPT(V2FORM, objDigest, OBJDIGEST,
                                          1)} ASN1_SEQUENCE_END(V2FORM)
        IMPLEMENT_ASN1_FUNCTIONS(V2FORM)
    /* ISSUERSERIAL */
    ASN1_SEQUENCE(ISSUERSERIAL) = {ASN1_SIMPLE(ISSUERSERIAL, issuer, GENERAL_NAMES),
                                   ASN1_SIMPLE(ISSUERSERIAL, subjectSN, ASN1_INTEGER),
                                   ASN1_OPT(ISSUERSERIAL, issuerUID,
                                            ASN1_BIT_STRING)} ASN1_SEQUENCE_END(ISSUERSERIAL)
        IMPLEMENT_ASN1_FUNCTIONS(ISSUERSERIAL)
    /* OBJDIGEST */
    ASN1_SEQUENCE(OBJDIGEST) = {ASN1_SIMPLE(OBJDIGEST, digestType, ASN1_ENUMERATED),
                                ASN1_OPT(OBJDIGEST, otherType, ASN1_OBJECT),
                                ASN1_SIMPLE(OBJDIGEST, digestAlg, X509_ALGOR),
                                ASN1_SIMPLE(OBJDIGEST, digestBit,
                                            ASN1_BIT_STRING)} ASN1_SEQUENCE_END(OBJDIGEST)
        IMPLEMENT_ASN1_FUNCTIONS(OBJDIGEST)
    /* X509V4_VALID */
    ASN1_SEQUENCE(X509V4_VALID) =
        {ASN1_SIMPLE(X509V4_VALID, notBefore, ASN1_GENERALIZEDTIME),
         ASN1_SIMPLE(X509V4_VALID, notAfter, ASN1_GENERALIZEDTIME)} ASN1_SEQUENCE_END(X509V4_VALID)
            IMPLEMENT_ASN1_FUNCTIONS(X509V4_VALID)
    /* X509V4_CINF */
    ASN1_SEQUENCE(
        X509V4_CINF) = {ASN1_SIMPLE(X509V4_CINF, version, ASN1_INTEGER),
                        ASN1_SIMPLE(X509V4_CINF, holder, ACHOLDER),
                        ASN1_SIMPLE(X509V4_CINF, issuer, ACISSUER),
                        ASN1_SIMPLE(X509V4_CINF, signature, X509_ALGOR),
                        ASN1_SIMPLE(X509V4_CINF, serialNumber, ASN1_INTEGER),
                        ASN1_SIMPLE(X509V4_CINF, valid, X509V4_VALID),
                        ASN1_SEQUENCE_OF(X509V4_CINF, attributes, X509_ATTRIBUTE),
                        ASN1_OPT(X509V4_CINF, issuerUID, ASN1_BIT_STRING),
                        ASN1_SEQUENCE_OF_OPT(X509V4_CINF, extensions,
                                             X509_EXTENSION)} ASN1_SEQUENCE_END(X509V4_CINF)
        IMPLEMENT_ASN1_FUNCTIONS(X509V4_CINF) ASN1_SEQUENCE(X509V4) = {
            ASN1_SIMPLE(X509V4, cert_info, X509V4_CINF), ASN1_SIMPLE(X509V4, sig_alg, X509_ALGOR),
            ASN1_SIMPLE(X509V4, signature, ASN1_BIT_STRING)} ASN1_SEQUENCE_END(X509V4)
```

