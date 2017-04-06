# 第三十二章 Openssl命令

## 32.1概述

​	Openssl命令源码位于apps目录下，编译的最终结果为openssl（windows下为openssl.exe）。用户可用运行openssl命令来进行各种操作。

## 32.2  asn1parse

​	asn1parse命令是一种用来诊断ASN.1结构的工具，也能用于从ASN1.1数据中提取数据。

​	用法：

```bash
openssl  asn1parse [-inform PEM|DER] [-in filename] [-out filename] [-noout] [-offset number] [-length number] [-i] [-oid filename] [-strparse offset] [-genstr string ] [-genconf file]
```

选项：

* -inform PEM|DER
  输入数据的格式为DER还是PEM，默认为PEM格式。
* -in filename
  输入文件名,默认为标准输入。
* -out filename
  输出文件名，默认为标准输出，给定一个PEM文件，采用此选项可用生成一个DER编码的文件。
* -noout
  无输出打印。
* -offset number
  数据分析字节偏移量，分析数据时，不一定从头开始分析，可用指定偏移量，默认从头开始分析。
* -length number
  分析数据的长度，默认的长度为整个数据的长度；
* -i
  标记实体，加上此选项后，输出会有缩进，将一个ASN1实体下的其他对象缩进显示。此选项非默认选项，加上此选项后，显示更易看懂。
* -dump
  显示十六进制数据。非默认选项。
* -dlimit number
  与dump不同，dump显示所有的数据，而此选项只能显示由number指定数目的十六进制数据。
* -oid file
  指定外部的oid文件。
* -strparse offset
  此选项也用于从一个偏移量开始来分析数据，不过，与offset不一样。offset分析偏移量之后的所有数据，而strparse只用于分析一段数据，并且这种数据必须是SET或者SEQUENCE，它只分析本SET或者SEQUENCE范围的数据。
  使用示例：输入文件为一个证书的PEM格式文件，文件名为server.pem，各种命令如下：

```bash
openssl  asn1parse serverr.pem
openssl  asn1parse –in server.pem –inform pem
```

​	上面的输出内容如下：

```bash
  0:d=0  hl=4 l= 489 cons: SEQUENCE
    4:d=1  hl=4 l= 338 cons: SEQUENCE
    8:d=2  hl=2 l=   1 prim: INTEGER           :06
   11:d=2  hl=2 l=  13 cons: SEQUENCE
   13:d=3  hl=2 l=   9 prim: OBJECT            :md5WithRSAEncryption
   24:d=3  hl=2 l=   0 prim: NULL
   26:d=2  hl=2 l=  91 cons: SEQUENCE
   28:d=3  hl=2 l=  11 cons: SET
   30:d=4  hl=2 l=   9 cons: SEQUENCE
   32:d=5  hl=2 l=   3 prim: OBJECT            :countryName
   37:d=5  hl=2 l=   2 prim: PRINTABLESTRING   :AU
   41:d=3  hl=2 l=  19 cons: SET
   43:d=4  hl=2 l=  17 cons: SEQUENCE
   45:d=5  hl=2 l=   3 prim: OBJECT            :stateOrProvinceName
   50:d=5  hl=2 l=  10 prim: PRINTABLESTRING   :Queensland
   62:d=3  hl=2 l=  26 cons: SET
   64:d=4  hl=2 l=  24 cons: SEQUENCE
………
```

​	以其中的一行进行说明：

```bash
13:d=3  hl=2 l=   9 prim: OBJECT            :md5WithRSAEncryption
```

​	13表示偏移量；d=3表示此项的深度；hl=2表示asn1头长度；l=9表示内容长度；prim:OBJECT表示ASN1类型；md5WithRSAEncryption表示oid。

​	示例如下：

```bash
openssl  asn1parse –in c:\server.pem –out c:\server.cer
```

​	此命令除了显示上面内容外，并生成一个der编码的文件。

```bash
openssl  asn1parse –in c:\server.pem –i
```

​	此命令从偏移量26开始分析，到结束。注意，26从前面命令的结果得到。

```bash
openssl  asn1parse –in c:\server.pem –i –offset 13 –length 11
```

​	此命令从偏移量13进行分析，分析长度为11

```bash
openssl  asn1parse –in c:\server.pem –i –dump
```

​	分析时，显示BIT STRING等的十六进制数据；

```bash
openssl  asn1parse –in c:\server.pem –i –dlimit 10
```

​	分析时，显示BIT SRING的前10个十六进制数据。

```bash
openssl  asn1parse –in c:\server.pem –i –strparse 11
```

​	此令分析一个SEQUENCE。

```bash
openssl  asn1parse –in c:\server.pem –i –strparse 11 –offset 2 –length 11
```

​	根据偏移量和长度分析。

## 32.3  dgst

       dgst用于数据摘要。

       用法：

```bash
openssl dgst [-md5|-md4|-md2|-sha1|-sha|-mdc2|-ripemd160|-dss1 ] [-c] [-d ] [-hex] [-binary] [-out filename] [-sign filename] [-passin arg] [-verify filename] [-prverify filename] [-signature filename ] [file…]
```

​	选项：

* -d
  打印调试信息。
* -signprivatekeyfile
  用privatekeyfile中的私钥签名。
* -verify    publickeyfile
  用publickeyfile中的公钥验证签名。
* -prverifyprivatekeyfile
  用privatekeyfile中的私钥验证签名。
* -keyform PEM |  ENGINE
  密钥格式，PEM格式或者采用Engine。
* -hex
  显示ASCII编码的十六进制结果，默认选项。
* -binary
  显示二进制数据。
* -engine    e
  采用引擎e来运算。
* -md5      
  默认选项，用md5进行摘要。
* -md4
  用md4摘要。
* -md2
  用md2摘要。
* -sha1
  用sha1摘要。
* -sha
  用sha摘要。
* -sha256
  用sha256摘要。
* -sha512
  用sha512摘要。
* -mdc2
  用mdc2摘要。
* -ripemd160
  用ripemd160摘要。

  ​

