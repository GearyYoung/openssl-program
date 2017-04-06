# 第二章 openssl简介

## 2.1  openssl简介

​	openssl是一个功能丰富且自包含的开源安全工具箱。它提供的主要功能有：SSL协议实现(包括SSLv2、SSLv3和TLSv1)、大量软算法(对称/非对称/摘要)、大数运算、非对称算法密钥生成、ASN.1编解码库、证书请求(PKCS10)编解码、数字证书编解码、CRL编解码、OCSP协议、数字证书验证、PKCS7标准实现和PKCS12个人数字证书格式实现等功能。

​	openssl采用C语言作为开发语言，这使得它具有优秀的跨平台性能。openssl支持Linux、UNIX、windows、Mac等平台。

## 2.2  openssl安装

​	对应不同的操作系统，用户可以参考INSTALL、INSTALL.MacOS、INSTALL.NW、INSTALL.OS2、INSTALL.VMS、INSTALL.W32、INSTALL.W64和INSTALL.WCE等文件来安装openssl。安装时，需要如下条件：

​	Make工具、Perl 5、编译器以及C语言库和头文件。

### 2.2.1  linux下的安装

1. 解压openssl开发包文件；
2. 运行./config –prefix=/usr/local/openssl  (更多选项用./config –help来查看),可用的选项有：no-mdc2、no-cast no-rc2、no-rc5、no-ripemd、no-rc4 no-des 、no-md2、no-md4、no-idea 、no-aes、no-bf、no-err、no-dsa、no-dh、no-ec、no-hw、no-asm、no-krb5、no-dso、no-threads 、no-zlib、-DOPENSSL_NO_HASH_COMP、-DOPENSSL_NO_ERR、-DOPENSSL_NO_HW 、-DOPENSSL_NO_OCSP、-DOPENSSL_NO_SHA256和-DOPENSSL_NO_SHA512等。去掉不必要的内容可以减少生成库的大小。 若要生成debug版本的库和可执行程序加-g或者-g3(openssl中有很多宏，需要调试学习最好加上-g3)。
3. make test   (可选)
4. make install

​	完成后,openssl会被安装到/usr/local/openssl目录，包括头文件目录include、可执行文件目录bin、man在线帮助、库目录lib以及配置文件目录(ssl)。

### 2.2.2  windows编译与安装

略

## 2.3  openssl源代码

​	openssl源代码主要由eay库、ssl库、工具源码、范例源码以及测试源码组成。

​	eay库是基础的库函数，提供了很多功能。源代码放在crypto目录下。包括如下内容：

1. asn.1 DER编码解码(crypto/asn1目录)，它包含了基本asn1对象的编解码以及数字证书请求、数字证书、CRL撤销列表以及PKCS8等最基本的编解码函数。这些函数主要通过宏来实现。
2. 抽象IO(BIO,crypto/bio目录)，本目录下的函数对各种输入输出进行抽象，包括文件、内存、标准输入输出、socket和SSL协议等。
3. 大数运算(crypto/bn目录)，本目录下的文件实现了各种大数运算。这些大数运算主要用于非对称算法中密钥生成以及各种加解密操作。另外还为用户提供了大量辅助函数，比如内存与大数之间的相互转换。
4. 字符缓存操作(crypto/buffer目录)。
5. 配置文件读取(crypto/conf目录)，openssl主要的配置文件为openssl.cnf。本目录下的函数实现了对这种格式配置文件的读取操作。
6. DSO(动态共享对象,crypto/dso目录)，本目录下的文件主要抽象了各种平台的动态库加载函数，为用户提供统一接口。
7. 硬件引擎(crypto/engine目录)，硬件引擎接口。用户如果要写自己的硬件引擎，必须实现它所规定的接口。
8. 错误处理(crypto/err目录)，当程序出现错误时，openssl能以堆栈的形式显示各个错误。本目录下只有基本的错误处理接口，具体的的错误信息由各个模块提供。各个模块专门用于错误处理的文件一般为*_err..c文件。
9. 对称算法、非对称算法及摘要算法封装(crypto/evp目录)。
10. HMAC(crypto/hmac目录)，实现了基于对称算法的MAC。
11. hash表(crypto/lhash目录)，实现了散列表数据结构。openssl中很多数据结构都是以散列表来存放的。比如配置信息、ssl session和asn.1对象信息等。
12. 数字证书在线认证(crypto/ocsp目录)，实现了ocsp协议的编解码以及证书有效性计算等功能。
13. PEM文件格式处理(crypto/pem)，用于生成和读取各种PEM格式文件，包括各种密钥、数字证书请求、数字证书、PKCS7消息和PKCS8消息等。
14. pkcs7消息语法(crypto/pkcs7目录)，主要实现了构造和解析PKCS7消息；
15. pkcs12个人证书格式(crypto/pckcs12目录)，主要实现了pkcs12证书的构造和解析。
16. 队列(crypto/pqueue目录)，实现了队列数据结构，主要用于DTLS。
17. 随机数(crypto/rand目录)，实现了伪随机数生成，支持用户自定义随机数生成。
18. 堆栈(crypto/stack目录)，实现了堆栈数据结构。
19. 线程支持(crypto/threads)，openssl支持多线程，但是用户必须实现相关接口。
20.  文本数据库(crypto/txt_db目录)。
21. x509数字证书(crypto/x509目录和crypto/x509v3)，包括数字证书申请、数字证书和CRL的构造、解析和签名验证等功能了；
22. 对称算法(crypto/aes、crypto/bf、crypto/cast、ccrypto/omp和crypto/des等目录)。
23. 非对称算法(crypto/dh、crypto/dsa、crypto/ec和crypto/ecdh)。
24. 摘要算法(crypto/md2、crypto/md4、crypto/md5和crypto/sha)以及密钥交换/认证算法(crypto/dh 和crypto/krb5)。

​	ssl库所有源代码在ssl目录下，包括了sslv2、sslv3、tlsv1和DTLS的源代码。各个版本基本上都有客户端源码(*_clnt.c)、服务源码(*_srvr.c)、通用源码(*_both.c)、底层包源码（*_pkt.c）、方法源码(*_meth.c)以及协议相关的各种密钥计算源码(*_enc.c)等，都很有规律。

​	工具源码主要在crypto/apps目录下，默认编译时只编译成openssl(windows下为openssl.exe)可执行文件。该命令包含了各种命令工具。此目录下的各个源码可以单独进行编译。

​	范例源码在demo目录下，另外engines目录给出了openssl支持的几种硬件的engines源码，也可以作为engine编写参考。

​	测试源码主要在test目录下。

## 2.4  openssl学习方法

​	通过学习openssl，用户能够学到PKI方面的各种知识，其重要性不言而喻。以下为学习openssl的方法，供参考。

1. 建立学习环境

   建立一个供调试的openssl环境，可以是windows平台，也可以是linux或者其他平台。用户需有在这些平台下调试源代码的能力。

2. 学习openssl的命令

   通过openssl命令的学习，对openssl有基本的了解。

3. 学习openssl源代码并调试

​	主要的源代码有：

> apps目录下的各个程序，对应于openssl的各项命令；
>
> demos下的各种源代码；
>
> engines下的各种engine实现；
>
> test目录下的各种源代码。

​	对于openssl函数的学习，主要查看openssl自身是如何调用的，或者查看函数的实现。对于openssl中只有实现而没有调用的函数，读者需要自己写源码或研究源代码去学习。

4. 学会使用openssl的asn.1编解码

   openssl中很多函数和源码都涉及到asn1编解码，比如数字证书申请、数字证书、crl、ocsp、pkcs7、pkcs8、pkcs12等。

5. 查找资料

   Linux下主要用man就能查看openssl命令和函数的帮助。Windows用户可用到www.openss.org去查看在线帮助文档，或者用linux下的命令man2html将帮助文档装换为html格式。用户也可以访问openssl.cn论坛来学习openssl。

6. 学习openssl相关书籍

   读者可以参考《OpenSSL与网络信息安全—基础、结构和指令》、《Network Security with OpenSSL》(OReilly出版)和《OpenSSL for windows Developer’s Guide》。