# 第三十一章 SSL实现

## 31.1概述

​	SSL协议最先由netscape公司提出，包括sslv2和sslv3两个版本。当前形成标准的为了tls协议(rfc2246规范)和DTLS（rfc4347，用于支持UDP协议）。sslv3和tls协议大致一样，只是有一些细微的差别。实际应用中，用的最多的为sslv3。

​	SSL协议能够保证通信双方的信道安全。它能提供数据加密、身份认证以及消息完整性保护，另外SSL协议还支持数据压缩。

​	SSL协议通过客户端和服务端握手来协商各种算法和密钥。

## 31.2  openssl实现

​	SSL协议源码位于ssl目录下。它实现了sslv2、sslv3、TLS以及DTLS（Datagram TLS，基于UDP的TLS实现）。ssl实现中，对于每个协议，都有客户端实现(XXX_clnt.c)、服务端实现(XXX_srvr.c)、加密实现(XXX_enc.c)、记录协议实现(XXX_pkt.c)、METHOD方法(XXX_meth.c)、客户端服务端都用到的握手方法实现(XXX_both.c)，以及对外提供的函数实现(XXX_lib.c)，比较有规律。

## 31.3  建立SSL测试环境

​	为了对SSL协议有大致的了解，我们可以通过openssl命令来建立一个SSL测试环境。

1. 建立自己的CA

    在openssl安装目录的misc目录下（或者在apps目录下），运行脚本：./CA.sh -newca（Windows环境下运行：perl ca.pl –newca），出现提示符时，直接回车。  运行完毕后会生成一个demonCA的目录，里面包含了ca证书及其私钥。

2. 生成客户端和服务端证书申请：

```bash
openssl req -newkey rsa:1024 -out req1.pem -keyout sslclientkey.pem
openssl req -newkey rsa:1024 -out req2.pem -keyout sslserverkey.pem
```

3. 签发客户端和服务端证书

```bash
openssl ca -in req1.pem -out  sslclientcert.pem
openssl ca -in req2.pem -out  sslservercert.pem
```

4. 运行ssl服务端和客户端：

```bash
openssl s_server -cert sslservercert.pem -key sslserverkey.pem -CAfile demoCA/cacert.pem -ssl3
openssl s_client -ssl3 -CAfile demoCA/cacert.pem
```

​	运行客户端程序后，如果正确，会打印类似如下内容:

```log
SSL-Session:
   Protocol  : SSLv3
Cipher    : DHE-RSA-AES256-SHA
    Session-ID: A729F5845CBFFBA68B27F701A6BD9D411627FA5BDC780264131EE966D1DFD6F5
    Session-ID-ctx:
    Master-Key: B00EEBD68165197BF033605F348A91676E872EB48487990D8BC77022578EECC0A9789CD1F929E6A9EA259F9F9F3F9DFA
    Key-Arg   : None
    Start Time: 1164077175
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
```

​	此时，输入数据然后回车，服务端会显示出来。

命令的其他选项：

* 验证客户端证书

```bash
openssl s_server -cert sslservercert.pem -key sslserverkey.pem -CAfile demoCA/cacert.pem -ssl3 -Verify 1
openssl s_client -ssl3 -CAfile demoCA/cacert.pem -cert sslclientcert.pem -key sslclientkey.pem
```

* 指定加密套件

```bash
openssl s_server -cert sslservercert.pem -key sslserverkey.pem -CAfile demoCA/cacert.pem -ssl3 -Verify 1
openssl s_client -ssl3 -CAfile demoCA/cacert.pem -cert sslclientcert.pem -key sslclientkey.pem -cipher AES256-SHA
```

​	其中AES256-SHA可用根据openssl ciphers命令获取，s_server也可用指明加密套件：

```bash
openssl s_server -cert sslservercert.pem -key sslserverkey.pem -CAfile demoCA/cacert.pem -ssl3 -Verify 1 -cipher AES256-SHA
```

* 指定私钥加密口令

```bash
openssl s_server -cert sslservercert.pem -key sslserverkey.pem -CAfile demoCA/cacert.pem -ssl3 -Verify 3 -cipher AES256-SHA -pass pass:123456
openssl s_client -ssl3 -CAfile demoCA/cacert.pem -cert sslclientcert.pem -key sslclientkey.pem -pass pass:123456
```

​	用参数pass给出私钥保护口令来源：

```bash
-pass file:1.txt   (1.txt的内容为加密口令123456）
-pass env:envname (环境变量）
-pass fd:fdname 
-pass stdin
```

​	比如：

```bash
openssl s_client -ssl3 -CAfile demoCA/cacert.pem -cert sslclientcert.pem -key sslclientkey.pem -pass stdin
```

​	然后输入口令123456即可。

## 31.4  数据结构

​	ssl的主要数据结构定义在ssl.h中。主要的数据结构有SSL_CTX、SSL和SSL_SESSION。SSL_CTX数据结构主要用于SSL握手前的环境准备，设置CA文件和目录、设置SSL握手中的证书文件和私钥、设置协议版本以及其他一些SSL握手时的选项。SSL数据结构主要用于SSL握手以及传送应用数据。SSL_SESSION中保存了主密钥、session id、读写加解密钥、读写MAC密钥等信息。SSL_CTX中缓存了所有SSL_SESSION信息，SSL中包含SSL_CTX。一般SSL_CTX的初始化在程序最开始调用，然后再生成SSL数据结构。由于SSL_CTX中缓存了所有的SESSION，新生成的SSL结构又包含SSL_CTX数据，所以通过SSL数据结构能查找以前用过的SESSION id，实现SESSION重用。

## 31.5  加密套件

​	一个加密套件指明了SSL握手阶段和通信阶段所应该采用的各种算法。这些算法包括：认证算法、密钥交换算法、对称算法和摘要算法等。

​	在握手初始化的时候，双方都会导入各自所认可的多种加密套件。在握手阶段，由服务端选择其中的一种加密套件。

​	OpenSSL的ciphers命令可以列出所有的加密套件。openssl的加密套件在s3_lib.c的ssl3_ciphers数组中定义。比如有：

```cpp
/* Cipher 05 */
{
    1, SSL3_TXT_RSA_RC4_128_SHA, SSL3_CK_RSA_RC4_128_SHA,
        SSL_kRSA | SSL_aRSA | SSL_RC4 | SSL_SHA1 | SSL_SSLV3, SSL_NOT_EXP | SSL_MEDIUM, 0, 128, 128,
        SSL_ALL_CIPHERS, SSL_ALL_STRENGTHS,
}
```

​	其中1表示是合法的加密套件；`SSL3_TXT_RSA_RC4_128_SHA`为加密套件的名字， `SSL3_CK_RSA_RC4_128_SHA`为加密套件ID，`SSL_kRSA|SSL_aRSA|SSL_RC4 |SSL_SHA1|SSL_SSLV3`表明了各种算法，其中密钥交换采用RSA算法（SSL_kRSA），认证采用RSA算法（SSL_aRSA），对称加密算法采用RC4算法(SSL_RC4)，摘要采用SHA1，采用SSL协议第三版本，`SSL_NOT_EXP|SSL_MEDIUM`表明算法的强度。

​	在客户端和服务器端建立安全连接之前，双方都必须指定适合自己的加密套件。加密套件的选择可以通过组合的字符串来控制。

​	字符串的形式举例：`ALL:!ADH:RC4+RSA:+SSLv2:@STRENGTH`。

​	Openssl定义了4中选择符号：“＋”，“－”，“！”，“@”。其中，“＋”表示取交集；“－”表示临时删除一个算法；“！”表示永久删除一个算法；“@“表示了排序方法。

​	多个描述之间可以用“：”、“，”、“ ”、“；”来分开。选择加密套件的时候按照从左到的顺序构成双向链表，存放与内存中。

​	`ALL:!ADH:RC4+RSA:+SSLv2:@STRENGTH`表示的意义是：首先选择所有的加密套件（不包含eNULL，即空对称加密算法），然后在得到的双向链表之中去掉身份验证采用DH的加密套件；加入包含RC4算法并将包含RSA的加密套件放在双向链表的尾部；再将支持SSLV2的加密套件放在尾部；最后得到的结果按照安全强度进行排序。

​	SSL建立链接之前，客户端和服务器端用openssl函数来设置自己支持的加密套件。主要的函数有：

```cpp
int SSL_set_cipher_list(SSL *s,const char *str)；
int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str)；
```

​	比如只设置一种加密套件：

```cpp
int   ret=SSL_set_cipher_list(ssl,"RC4-MD5");
```

​	如果服务端只设置了一种加密套件，那么客户端要么接受要么返回错误。加密套件的选择是由服务端做出的。

## 31.6  密钥信息

​	ssl中的密钥相关信息包括：预主密钥、主密钥、读解密密钥及其iv、写加密密钥及其iv、读MAC密钥、写MAC密钥。

1. 预主密钥
   预主密钥是主密钥的计算来源。它由客户端生成，采用服务端的公钥加密发送给服务端。
   以sslv3为例，预主密钥的生成在源代码s3_clnt.c的ssl3_send_client_key_exchange函数中，有源码如下：

```cpp
tmp_buf[0]=s->client_version>>8;
tmp_buf[1]=s->client_version&0xff;
if (RAND_bytes(&(tmp_buf[2]),sizeof tmp_buf-2) <= 0)
	goto err;
s->session->master_key_length=sizeof tmp_buf;
……
n=RSA_public_encrypt(sizeof tmp_buf,tmp_buf,p,rsa,RSA_PKCS1_PADDING);
```

​	此处，tmp_buf中存放的就是预主密钥。

2. 主密钥

   主密钥分别由客户端和服务端根据预主密钥、客户端随机数和服务端随机数来生成，他们的主密钥是相同的。主密钥用于生成各种密钥信息，它存放在SESSION数据结构中。由于协议版本不同，生成方式也不同。sslv3的源代码中，它通过ssl3_generate_master_secret函数生成，tlsv1中它通过tls1_generate_master_secret函数来生成。

3. 对称密钥和MAC密钥

   对称密钥（包括IV）和读写MAC密钥通过主密钥、客户端随机数和服务端随机数来生成。sslv3源代码中，它们在ssl3_generate_key_block中生成，在ssl3_change_cipher_state中分配。

## 31.7  SESSION

​	当客户端和服务端在握手中新建了session，服务端生成一个session ID，通过哈希表缓存SESSION信息，并通过server hello消息发送给客户端。此ID是一个随机数，SSL v2版本时长度为16字节，SSLv3和TLSv1长度为32字节。此ID与安全无关，但是在服务端必须是唯一的。当需要session重用时，客户端发送包含session id的clientHello消息（无sesion重用时，此值为空）给服务端，服务端可用根据此ID来查询缓存。session重用可以免去诸多SSL握手交互，特别是客户端的公钥加密和服务端的私钥解密所带来的性能开销。session的默认超时时间为60*5+4秒，5分钟。

​	session相关函数有：

1. `int SSL_has_matching_session_id(const SSL *ssl, const unsigned char *   id,unsigned int id_len)`
   SSL中查询session id，id和 id_len为输入的要查询的session id，查询哈希表ssl->ctx->sessions，如果匹配，返回1，否则返回0。
2. `int ssl_get_new_session(SSL *s, int session)`
   生成ssl用的session，此函数可用被服务端或客户端调用，当服务端调用时，传入参数session为1，生成新的session；当客户端调用时，传入参数session为0，只是简单的将session id的长度设为0。
3. `int ssl_get_prev_session(SSL *s, unsigned char *session_id, int len)`
   获取以前用过的session id，用于服务端session重用，本函数由服务端调用，session_id为输入senssion ID首地址，len为其长度，如果返回1，表明要session重用；返回0，表示没有找到；返回-1表示错误。
4. `int SSL_set_session(SSL *s, SSL_SESSION *session)`
   设置session，本函数用于客户端，用于设置session信息；如果输入参数session为空值，它将置空s->session；如果不为空，它将输入信息作为session信息。
5. `void SSL_CTX_flush_sessions(SSL_CTX *s, long t)`
   清除超时的SESSION，输入参数t指定一个时间，如果t=0,则清除所有SESSION，一般用time(NULL)取当前时间。此函数调用了哈希表函数lh_doall_arg来处理每一个SESSION数据。
6. `int ssl_clear_bad_session(SSL *s)`
   清除无效SESSION。

   ​

## 31.8  多线程支持

​	编写openssl多线程程序时，需要设置两个回调函数：

```cpp
CRYPTO_set_id_callback((unsigned long (*)())pthreads_thread_id);
CRYPTO_set_locking_callback((void (*)())pthreads_locking_callback);
```

​	对于多线程程序的写法，读者可以参考crypto/threads/mttest.c，也可以查考下面的例子。

## 31.9  编程示例

​	本示例用多线程实现了一个ssl服务端和一个客户端。

​	服务端代码如下：

```cpp
#include <errno.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef _WIN32
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#else
#include <windows.h>
#include <winsock2.h>
#endif
#include "pthread.h"
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#define CERTF "certs/sslservercert.pem"
#define KEYF "certs/sslserverkey.pem"
#define CAFILE "certs/cacert.pem"
pthread_mutex_t mlock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t* lock_cs;
static long* lock_count;
#define CHK_NULL(x)                                                                                \
    if ((x) == NULL) {                                                                             \
        printf("null\n");                                                                          \
    }
#define CHK_ERR(err, s)                                                                            \
    if ((err) == -1) {                                                                             \
        printf(" -1 \n");                                                                          \
    }
#define CHK_SSL(err)                                                                               \
    if ((err) == -1) {                                                                             \
        printf(" -1 \n");                                                                          \
    }
#define CAFILE "certs/cacert.pem"
int verify_callback_server(int ok, X509_STORE_CTX* ctx) {
    printf("verify_callback_server \n");
    return ok;
}
int SSL_CTX_use_PrivateKey_file_pass(SSL_CTX* ctx, char* filename, char* pass) {
    EVP_PKEY* pkey = NULL;
    BIO* key = NULL;
    key = BIO_new(BIO_s_file());
    BIO_read_filename(key, filename);
    pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, pass);
    if (pkey == NULL) {
        printf("PEM_read_bio_PrivateKey err");
        return -1;
    }
    if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0) {
        printf("SSL_CTX_use_PrivateKey err\n");
        return -1;
    }
    BIO_free(key);
    return 1;
}
static int s_server_verify = SSL_VERIFY_NONE;
void* thread_main(void* arg) {
    SOCKET s, AcceptSocket;
    WORD wVersionRequested;
    WSADATA wsaData;
    struct sockaddr_in service;
    int err;
    size_t client_len;
    SSL_CTX* ctx;
    SSL* ssl;
    X509* client_cert;
    char* str;
    char buf[1024];
    SSL_METHOD* meth;
    ssl = (SSL*)arg;
    s = SSL_get_fd(ssl);
    err = SSL_accept(ssl);
    if (err < 0) {
        printf("ssl accerr\n");
        return;
    }
    printf("SSL connection using %s\n", SSL_get_cipher(ssl));
    client_cert = SSL_get_peer_certificate(ssl);
    if (client_cert != NULL) {
        printf("Client certificate:\n");
        str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
        CHK_NULL(str);
        printf("\t subject: %s\n", str);
        OPENSSL_free(str);
        str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
        CHK_NULL(str);
        printf("\t issuer: %s\n", str);
        OPENSSL_free(str);
        X509_free(client_cert);
    } else
        printf("Client does not have certificate.\n");
    memset(buf, 0, 1024);
    err = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (err < 0) {
        printf("ssl read err\n");
        closesocket(s);
        return;
    }
    printf("get : %s\n", buf);
#if 0
      buf[err] = '\0';
    err = SSL_write (ssl, "I hear you.", strlen("I hear you."));  CHK_SSL(err);
#endif
    SSL_free(ssl);
    closesocket(s);
}
pthread_t pthreads_thread_id(void) {
    pthread_t ret;
    ret = pthread_self();
    return (ret);
}
void pthreads_locking_callback(int mode, int type, char* file, int line) {
    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&(lock_cs[type]));
        lock_count[type]++;
    } else {
        pthread_mutex_unlock(&(lock_cs[type]));
    }
}
int main() {
    int err;
    int i;
    SOCKET s, AcceptSocket;
    WORD wVersionRequested;
    WSADATA wsaData;
    struct sockaddr_in service;
    pthread_tpid;
    size_t client_len;
    SSL_CTX* ctx;
    SSL* ssl;
    X509* client_cert;
    char* str;
    char buf[1024];
    SSL_METHOD* meth;
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
    meth = SSLv3_server_method();
    ctx = SSL_CTX_new(meth);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(2);
    }
    if ((!SSL_CTX_load_verify_locations(ctx, CAFILE, NULL)) ||
        (!SSL_CTX_set_default_verify_paths(ctx))) {
        printf("err\n");
        exit(1);
    }
    if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(3);
    }
    if (SSL_CTX_use_PrivateKey_file_pass(ctx, KEYF, "123456") <= 0) {
        ERR_print_errors_fp(stderr);
        exit(4);
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        exit(5);
    }
    s_server_verify = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_CLIENT_ONCE;
    SSL_CTX_set_verify(ctx, s_server_verify, verify_callback_server);
    SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(CAFILE));
    wVersionRequested = MAKEWORD(2, 2);
    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        printf("err\n");
        return -1;
    }
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0)
        return -1;
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = inet_addr("127.0.0.1");
    service.sin_port = htons(1111);
    if (bind(s, (SOCKADDR*)&service, sizeof(service)) == SOCKET_ERROR) {
        printf("bind() failed.\n");
        closesocket(s);
        return -1;
    }
    if (listen(s, 1) == SOCKET_ERROR)
        printf("Error listening on socket.\n");
    printf("recv .....\n");
    lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        lock_count[i] = 0;
        pthread_mutex_init(&(lock_cs[i]), NULL);
    }
    CRYPTO_set_id_callback((unsigned long (*)())pthreads_thread_id);
    CRYPTO_set_locking_callback((void (*)())pthreads_locking_callback);
    while (1) {
        struct timeval tv;
        fd_set fdset;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        FD_ZERO(&fdset);
        FD_SET(s, &fdset);
        select(s + 1, &fdset, NULL, NULL, (struct timeval*)&tv);
        if (FD_ISSET(s, &fdset)) {
            AcceptSocket = accept(s, NULL, NULL);
            ssl = SSL_new(ctx);
            CHK_NULL(ssl);
            err = SSL_set_fd(ssl, AcceptSocket);
            if (err > 0) {
                err = pthread_create(&pid, NULL, &thread_main, (void*)ssl);
                pthread_detach(pid);
            } else
                continue;
        }
    }
    SSL_CTX_free(ctx);
    return 0;
}
```

​	客户端代码如下：

```cpp
#include <errno.h>
#include <memory.h>
#include <stdio.h>
#ifndef _WIN32
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#else
#include <windows.h>
#endif
#include "pthread.h"
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#define MAX_T 1000
#define CLIENTCERT "certs/sslclientcert.pem"
#define CLIENTKEY "certs/sslclientkey.pem"
#define CAFILE "certs/cacert.pem"
static pthread_mutex_t* lock_cs;
static long* lock_count;
pthread_t pthreads_thread_id(void) {
    pthread_t ret;
    ret = pthread_self();
    return (ret);
}
void pthreads_locking_callback(int mode, int type, char* file, int line) {
    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&(lock_cs[type]));
        lock_count[type]++;
    } else {
        pthread_mutex_unlock(&(lock_cs[type]));
    }
}
int verify_callback(int ok, X509_STORE_CTX* ctx) {
    printf("verify_callback\n");
    return ok;
}
int SSL_CTX_use_PrivateKey_file_pass(SSL_CTX* ctx, char* filename, char* pass) {
    EVP_PKEY* pkey = NULL;
    BIO* key = NULL;
    key = BIO_new(BIO_s_file());
    BIO_read_filename(key, filename);
    pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, pass);
    if (pkey == NULL) {
        printf("PEM_read_bio_PrivateKey err");
        return -1;
    }
    if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0) {
        printf("SSL_CTX_use_PrivateKey err\n");
        return -1;
    }
    BIO_free(key);
    return 1;
}
void* thread_main(void* arg) {
    int err, buflen, read;
    int sd;
    SSL_CTX* ctx = (SSL_CTX*)arg;
    struct sockaddr_in dest_sin;
    SOCKET sock;
    PHOSTENT phe;
    WORD wVersionRequested;
    WSADATA wsaData;
    SSL* ssl;
    X509* server_cert;
    char* str;
    char buf[1024];
    SSL_METHOD* meth;
    FILE* fp;
    wVersionRequested = MAKEWORD(2, 2);
    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        printf("WSAStartup err\n");
        return -1;
    }
    sock = socket(AF_INET, SOCK_STREAM, 0);
    dest_sin.sin_family = AF_INET;
    dest_sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    dest_sin.sin_port = htons(1111);
again:
    err = connect(sock, (PSOCKADDR)&dest_sin, sizeof(dest_sin));
    if (err < 0) {
        Sleep(1);
        goto again;
    }
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        printf("ss new err\n");
        return;
    }
    SSL_set_fd(ssl, sock);
    err = SSL_connect(ssl);
    if (err < 0) {
        printf("SSL_connect err\n");
        return;
    }
    printf("SSL connection using %s\n", SSL_get_cipher(ssl));
    server_cert = SSL_get_peer_certificate(ssl);
    printf("Server certificate:\n");
    str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
    printf("\t subject: %s\n", str);
    OPENSSL_free(str);
    str = X509_NAME_oneline(X509_get_issuer_name(server_cert), 0, 0);
    printf("\t issuer: %s\n", str);
    OPENSSL_free(str);
    X509_free(server_cert);
    err = SSL_write(ssl, "Hello World!", strlen("Hello World!"));
    if (err < 0) {
        printf("ssl write err\n");
        return;
    }
#if 0
       memset(buf,0,ONE_BUF_SIZE);
      err = SSL_read (ssl, buf, sizeof(buf) - 1);
       if(err<0)
       {
              printf("ssl read err\n");
              return ;
       }
      buf[err] = '\0';
      printf ("Got %d chars:'%s'\n", err, buf);
#endif
    SSL_shutdown(ssl); /* send SSL/TLS close_notify */
    SSL_free(ssl);
    closesocket(sock);
}
int main() {
    int err, buflen, read;
    int sd;
    struct sockaddr_in dest_sin;
    SOCKETsock;
    PHOSTENT phe;
    WORD wVersionRequested;
    WSADATA wsaData;
    SSL_CTX* ctx;
    SSL* ssl;
    X509* server_cert;
    char* str;
    char buf[1024];
    SSL_METHOD* meth;
    int i;
    pthread_tpid[MAX_T];
    SSLeay_add_ssl_algorithms();
    meth = SSLv3_client_method();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(meth);
    if (ctx == NULL) {
        printf("ssl ctx new eer\n");
        return -1;
    }
    if (SSL_CTX_use_certificate_file(ctx, CLIENTCERT, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(3);
    }
    if (SSL_CTX_use_PrivateKey_file_pass(ctx, CLIENTKEY, "123456") <= 0) {
        ERR_print_errors_fp(stderr);
        exit(4);
    }
    lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        lock_count[i] = 0;
        pthread_mutex_init(&(lock_cs[i]), NULL);
    }
    CRYPTO_set_id_callback((unsigned long (*)())pthreads_thread_id);
    CRYPTO_set_locking_callback((void (*)())pthreads_locking_callback);
    for (i = 0; i < MAX_T; i++) {
        err = pthread_create(&(pid[i]), NULL, &thread_main, (void*)ctx);
        if (err != 0) {
            printf("pthread_create err\n");
            continue;
        }
    }
    for (i = 0; i < MAX_T; i++) {
        pthread_join(pid[i], NULL);
    }
    SSL_CTX_free(ctx);
    printf("test ok\n");
    return 0;
}
```

​	上述程序在windows下运行成功，采用了windows下的开源pthread库。需要注意的是，如果多线程用openssl,需要设置两个回调函数：

```cpp
CRYPTO_set_id_callback((unsigned long (*)())pthreads_thread_id);
CRYPTO_set_locking_callback((void (*)())pthreads_locking_callback);
```

## 31.10函数

1. `SSL_accept`
   对应于socket函数accept，该函数在服务端调用，用来进行SSL握手。
2. `int SSL_add_client_CA(SSL *ssl,X509 *x)`
   添加客户端CA名。
3. `const char *SSL_alert_desc_string_long(int value)`
   根据错误号得到错误原因。
4. `SSL_check_private_key`
   检查SSL结构中的私钥。
5. `SSL_CIPHER_description`
   获取SSL加密套件描述。
6. `SSL_CIPHER_get_bits`
   获取加密套件中对称算法的加密长度。
7. `SSL_CIPHER_get_name`
   得到加密套件的名字。
8. `SSL_CIPHER_get_version`
   根据加密套件获取SSL协议版本。
9. `SSL_clear`
   清除SSL结构。
10. `SSL_connect`
   对应于socket函数connect，该函数在客户端调用，用来进行SSL握手。
11. `SSL_CTX_add_client_CA`
   给SSL_CTX添加客户端CA。
12. `int SSL_CTX_add_session(SSL_CTX *ctx, SSL_SESSION *c)`
   往SSL_CTX添加session。
13. `SSL_CTX_check_private_key`
   检查私钥。
14. `SSL_CTX_free`
   释放SSL_CTX空间。
15. `long SSL_CTX_get_timeout(const SSL_CTX *s)`
   获取超时时间。
16. `SSL_CTX_get_verify_callback`
   获取证书验证回调函数。
17. `SSL_CTX_get_verify_depth`
   获取证书验证深度。
18. `SSL_CTX_get_verify_mode`
   获取验证方式，这些值在ssl.h中定义如下：
```
#define SSL_VERIFY_NONE 0x00
#define SSL_VERIFY_PEER 0x01
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT 0x02
#define SSL_VERIFY_CLIENT_ONCE  0x04
```
19. `SSL_get_current_cipher`
    获取当前的加密套件。
20. `SSL_get_fd`
    获取链接句柄。
21. `SSL_get_peer_certificate`
    获取对方证书。
22. `XXX_client/server_method`
    获取各个版本的客户端和服务端的SSL方法。
23. `SSL_read`
    读取数据。
24. `SSL_write`
    发送数据。
25. `SSL_set_fd`
    设置SSL的链接句柄。
26. `SSL_get_current_compression`
    获取当前的压缩算法的COMP_METHOD。
27. `SSL_get_current_expansion`
    获取当前的解压算法的COMP_METHOD。
28. `SSL_COMP_get_name`
    获取压缩/解压算法的名称。
29. `SSL_CTX_set/get_ex_data`
    设置/读取用户扩展数据。
30. `SSL_dup`
    复制函数。
31. `SSL_get_default_timeout`
    获取默认超时时间。
32. `SSL_do_handshake`
    进行ssl握手。