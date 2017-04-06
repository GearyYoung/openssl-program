# 第十二章 BASE64编解码

## 12.1  BASE64编码介绍

​	BASE64编码是一种常用的将十六进制数据转换为可见字符的编码。与ASCII码相比，它占用的空间较小。BASE64编码在rfc3548中定义。

## 12.2  BASE64编解码原理

​	将数据编码成BASE64编码时，以3字节数据为一组，转换为24bit的二进制数，将24bit的二进制数分成四组，每组6bit。对于每一组，得到一个数字：0-63。然后根据这个数字查表即得到结果。表如下：

     

| Value | Char | Value | Char | Value | Char | Value | Char |
| ----- | ---- | ----- | ---- | ----- | ---- | ----- | ---- |
| 0     | A    | 16    | Q    | 32    | g    | 48    | w    |
| 1     | B    | 17    | R    | 33    | h    | 49    | x    |
| 2     | C    | 18    | S    | 34    | i    | 50    | y    |
| 3     | D    | 19    | T    | 35    | j    | 51    | z    |
| 4     | E    | 20    | U    | 36    | k    | 52    | 0    |
| 5     | F    | 21    | V    | 37    | l    | 53    | 1    |
| 6     | G    | 22    | W    | 38    | m    | 54    | 2    |
| 7     | H    | 23    | X    | 39    | n    | 55    | 3    |
| 8     | I    | 24    | Y    | 40    | o    | 56    | 4    |
| 9     | J    | 25    | Z    | 41    | p    | 57    | 5    |
| 10    | K    | 26    | a    | 42    | q    | 58    | 6    |
| 11    | L    | 27    | b    | 43    | r    | 59    | 7    |
| 12    | M    | 28    | c    | 44    | s    | 60    | 8    |
| 13    | N    | 29    | d    | 45    | t    | 61    | 9    |
| 14    | O    | 30    | e    | 46    | u    | 62    | +    |
| 15    | P    | 31    | f    | 47    | v    | 63    | /    |

       比如有数据：0x30 0x82 0x02

       编码过程如下：

       1）得到16进制数据： 30 82 02

       2）得到二进制数据： 00110000              10000010       00000010

       3）每6bit分组：        001100    001000    001000    000010

       4）得到数字：            12   8     8     2

       5）根据查表得到结果 ： M I I C

       BASE64填充：在不够的情况下在右边加0。 

       有三种情况：

       1)    输入数据比特数是24的整数倍（输入字节为3字节整数倍），则无填充；

       2)    输入数据最后编码的是1个字节(输入数据字节数除3余1)，即8比特，则需要填充2个“==”，因为要补齐6比特，需要加2个00；

       3）输入数据最后编码是2个字节(输入数据字节数除3余2)，则需要填充1个“=”，因为补齐6比特，需要加一个00。

       举例如下：

       对0x30编码：

       1)    0x30的二进制为：00110000

       2)    分组为：001100    00

       3)    填充2个00：001100   000000

       4)    得到数字：12 0

       5)    查表得到的编码为MA，另外加上两个==

       所以最终编码为：MA==

       base64解码是其编码过程的逆过程。解码时，将base64编码根据表展开，根据有几个等号去掉结尾的几个00，然后每8比特恢复即可。

## 12.3  主要函数

       Openssl中用于base64编解码的函数主要有：

1）  编码函数

Ø  EVP_EncodeInit

                     编码前初始化上下文。

Ø  EVP_EncodeUpdate

                     进行BASE64编码，本函数可多次调用。

Ø  EVP_EncodeFinal

                     进行BASE64编码，并输出结果。

Ø  EVP_EncodeBlock

              进行BASE64编码。

2）  解码函数

Ø  EVP_DecodeInit

解码前初始化上下文。

Ø  EVP_DecodeUpdate

BASE64解码，本函数可多次调用。

Ø  EVP_DecodeFinal

BASE64解码，并输出结果。

Ø  EVP_DecodeBlock

BASE64解码，可单独调用。

## 12.4  编程示例

**示例1**

```cpp
#include <openssl/evp.h>
#include <string.h>
int main() {
    EVP_ENCODE_CTX ectx, dctx;
    unsigned char in[500], out[800], d[500];
    int inl, outl, i, total, ret, total2;
    EVP_EncodeInit(&ectx);
    for (i = 0; i < 500; i++)
        memset(&in[i], i, 1);
    inl = 500;
    total = 0;
    EVP_EncodeUpdate(&ectx, out, &outl, in, inl);
    total += outl;
    EVP_EncodeFinal(&ectx, out + total, &outl);
    total += outl;
    printf("%s\n", out);
    EVP_DecodeInit(&dctx);
    outl = 500;
    total2 = 0;
    ret = EVP_DecodeUpdate(&dctx, d, &outl, out, total);
    if (ret < 0) {
        printf("EVP_DecodeUpdate err!\n");
        return -1;
    }
    total2 += outl;
    ret = EVP_DecodeFinal(&dctx, d, &outl);
    total2 += outl;
    return 0;
}
```

       本例中先编码再解码。

       编码调用次序为EVP_EncodeInit、EVP_EncodeUpdate(可以多次)和EVP_EncodeFinal。

       解码调用次序为EVP_DecodeInit、EVP_DecodeUpdate(可以多次)和EVP_DecodeFinal。

​	*注意：采用上述函数BASE64编码的结果不在一行，解码所处理的数据也不在一行。用上述函数进行BASE64编码时，输出都是格式化输出。特别需要注意的是，BASE64解码时如果某一行字符格式超过80个，会出错。如果要BASE64编码的结果不是格式化的，可以直接调用函数：EVP_EncodeBlock。同样对于非格式化数据的BASE64解码可以调用EVP_DecodeBlock函数，不过用户需要自己去除后面填充的0。*

**示例2**

```cpp
#include <openssl/evp.h>
#include <string.h>
int main() {
    unsigned char in[500], out[800], d[500], *p;
    int inl, i, len, pad;
    for (i = 0; i < 500; i++)
        memset(&in[i], i, 1);
    printf("please input how much(<500) to base64 : \n");
    scanf("%d", &inl);
    len = EVP_EncodeBlock(out, in, inl);
    printf("%s\n", out);
    p = out + len - 1;
    pad = 0;
    for (i = 0; i < 4; i++) {
        if (*p == '=')
            pad++;
        p--;
    }
    len = EVP_DecodeBlock(d, out, len);
    len -= pad;
    if ((len != inl) || (memcmp(in, d, len)))
        printf("err!\n");
    printf("test ok.\n");
    return 0;
}
```
