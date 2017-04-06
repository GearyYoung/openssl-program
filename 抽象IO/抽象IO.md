# 第七章 抽象IO

## 7.1 openssl抽象IO

​	openssl抽象IO(I/O abstraction，即BIO)是openssl对于io类型的抽象封装，包括：内存、文件、日志、标准输入输出、socket（TCP/UDP）、加/解密、摘要和ssl通道等。Openssl BIO通过回调函数为用户隐藏了底层实现细节，所有类型的bio的调用大体上是类似的。Bio中的数据能从一个BIO传送到另外一个BIO或者是应用程序。

## 7.2 数据结构

​	BIO数据结构主要有2个，在crypto/bio.h中定义如下：

1. BIO_METHOD

```cpp
typedef struct bio_method_st {
    int type;
    const char* name;
    int (*bwrite)(BIO*, const char*, int);
    int (*bread)(BIO*, char*, int);
    int (*bputs)(BIO*, const char*);
    int (*bgets)(BIO*, char*, int);
    long (*ctrl)(BIO*, int, long, void*);
    int (*create)(BIO*);
    int (*destroy)(BIO*);
    long (*callback_ctrl)(BIO*, int, bio_info_cb*);
} BIO_METHOD;
```

​	该结构定义了IO操作的各种回调函数，根据需要，具体的bio类型必须实现其中的一种或多种回调函数，各项意义如下：

* type：具体BIO类型；
* name：具体BIO的名字；
* bwrite：具体BIO写操作回调函数；
* bread：具体BIO读操作回调函数；
* bputs：具体BIO中写入字符串回调函数；
* bgets：具体BIO中读取字符串函数；
* ctrl：具体BIO的控制回调函数；
* create：生成具体BIO回调函数；
* destroy：销毁具体BIO回调函数；


* callback_ctrl：具体BIO控制回调函数，与ctrl回调函数不一样，该函数可由调用者（而不是实现者）来实现，然后通过BIO_set_callback等函数来设置。

2. BIO

```cpp
struct bio_st {
    BIO_METHOD* method;
    /* bio, mode, argp, argi, argl, ret */
    long (*callback)(struct bio_st*, int, const char*, int, long, long);
    char* cb_arg; /* first argument for the callback */
    int init;
    int shutdown;
    int flags; /* extra storage */
    int retry_reason;
    int num;
    void* ptr;
    struct bio_st* next_bio; /* used by filter BIOs */
    struct bio_st* prev_bio; /* used by filter BIOs */
    int references;
    nsigned long num_read;
    unsigned long num_write;
    CRYPTO_EX_DATA ex_data;
};
```

​	主要项含义：

* init：具体句柄初始化标记，初始化后为1。比如文件BIO中，通过BIO_set_fp关联一个文件指针时，该标记则置1；socket BIO中通过BIO_set_fd关联一个链接时设置该标记为1。
* shutdown：BIO关闭标记，当该值不为0时，释放资源；改值可以通过控制函数来设置。
* flags：有些BIO实现需要它来控制各个函数的行为。比如文件BIO默认该值为BIO_FLAGS_UPLINK，这时文件读操作调用UP_fread函数而不是调用fread函数。
* retry_reason：重试原因，主要用在socket和ssl BIO 的异步阻塞。比如socket bio中，遇到WSAEWOULDBLOCK错误时，openssl告诉用户的操作需要重试。
* num：该值因具体BIO而异，比如socket BIO中num用来存放链接字。
* ptr：指针，具体bio有不同含义。比如文件BIO中它用来存放文件句柄；mem bio中它用来存放内存地址；connect bio中它用来存放BIO_CONNECT数据，accept bio中它用来存放BIO_ACCEPT数据。
* next_bio：下一个BIO地址，BIO数据可以从一个BIO传送到另一个BIO，该值指明了下一个BIO的地址。
* references：被引用数量。
* num_read：BIO中已读取的字节数。
* num_write：BIO中已写入的字节数。
* ex_data：用于存放额外数据。

## 7.3 BIO 函数

​	BIO各个函数定义在crypto/bio.h中。所有的函数都由BIO_METHOD中的回调函数来实现。函数主要分为几类：

1. 具体BIO相关函数

   比如：BIO_new_file（生成新文件）和BIO_get_fd（设置网络链接）等。

2. 通用抽象函数

   比如BIO_read和BIO_write等。

​	另外，有很多函数是由宏定义通过控制函数BIO_ctrl实现，比如BIO_set_nbio、BIO_get_fd和BIO_eof等等。

## 7.4 编程示例

### 7.4.1 mem bio

```cpp
#include <openssl/bio.h>
#include <stdio.h>
int main() {
    BIO* b = NULL;
    int len = 0;
    char* out = NULL;

    b = BIO_new(BIO_s_mem()); // 生成一个mem类型的BIO。
    len = BIO_write(b, "openssl", 4); // 将字符串”openssl”写入bio。
    len = BIO_printf(b, "%s", "zcp"); // 将字符串”bio test”写入bio。
    len = BIO_ctrl_pending(b); // 得到缓冲区中待读取大小。
    out = (char*)OPENSSL_malloc(len); // 将bio中的内容写入out缓冲区。
    len = BIO_read(b, out, len);
    OPENSSL_free(out);
    BIO_free(b);
    return 0;
}
```

### 7.4.2 file bio

```cpp
#include <openssl/bio.h>
#include <stdio.h>
int main() {
    BIO* b = NULL;
    int len = 0, outlen = 0;
    char* out = NULL;

    b = BIO_new_file("bf.txt", "w");
    len = BIO_write(b, "openssl", 4);
    len = BIO_printf(b, "%s", "zcp");
    BIO_free(b);
    b = BIO_new_file("bf.txt", "r");
    len = BIO_pending(b);
    len = 50;
    out = (char*)OPENSSL_malloc(len);
    len = 1;
    while (len > 0) {
        len = BIO_read(b, out + outlen, 1);
        outlen += len;
    }
    BIO_free(b);
    free(out);
    return 0;
}
```

### 7.4.3 socket bio

​	服务端：

```cpp
#include <openssl/bio.h>
#include <stdio.h>
#include <string.h>
int main() {
    BIO *b = NULL, *c = NULL;
    int sock, ret, len;
    char* addr = NULL;
    char out[80];

    sock = BIO_get_accept_socket("2323", 0);
    b = BIO_new_socket(sock, BIO_NOCLOSE);
    ret = BIO_accept(sock, &addr);
    BIO_set_fd(b, ret, BIO_NOCLOSE);

    while (1) {
        memset(out, 0, 80);
        len = BIO_read(b, out, 80);
        if (out[0] == 'q')
            break;
        printf("%s", out);
    }
    BIO_free(b);
    return 0;
}
```

​	客户端telnet此端口成功后，输入字符，服务端会显示出来(linux下需要输入回车)。	客户端：

```cpp
#include <openssl/bio.h>
int main() {
    BIO *cbio, *out;
    int len;
    char tmpbuf[1024];
    cbio = BIO_new_connect("localhost:http");  //用来生成建立连接到本地web服务的BIO。
    out = BIO_new_fp(stdout, BIO_NOCLOSE);     //生成一个输出到屏幕的BIO。
    if (BIO_do_connect(cbio) <= 0) {
        fprintf(stderr, "Error connecting to server\n");
    }
    BIO_puts(cbio, "GET / HTTP/1.0\n\n");  //通过BIO发送数据。
    for (;;) {
        //将web服务响应的数据写入缓存,此函数循环调用直到无数据。
        len = BIO_read(cbio, tmpbuf, 1024);
        if (len <= 0)
            break;
        BIO_write(out, tmpbuf, len);  //通过BIO打印收到的数据。
    }
    BIO_free(cbio);
    BIO_free(out);
    return 0;
}
```

### 7.4.4 md BIO

```cpp
#include <openssl/bio.h>
#include <openssl/evp.h>
int main() {
    BIO *bmd = NULL, *b = NULL;
    const EVP_MD* md = EVP_md5();
    int len;
    char tmp[1024];

    bmd = BIO_new(BIO_f_md());         //生成一个md BIO。
    BIO_set_md(bmd, md);               //设置md BIO 为md5 BIO。
    b = BIO_new(BIO_s_null());         //生成一个null BIO。
    b = BIO_push(bmd, b);              //构造BIO 链,md5 BIO在顶部。
    len = BIO_write(b, "openssl", 7);  //将字符串送入BIO做摘要。
    len = BIO_gets(b, tmp, 1024);      //将摘要结果写入tmp缓冲区。
    BIO_free(b);
    return 0;
}
```

### 7.4.5 cipher BIO

```cpp
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <string.h>
int main() {
    /* 加密 */
    BIO *bc = NULL, *b = NULL;
    const EVP_CIPHER* c = EVP_des_ecb();
    int len, i;
    char tmp[1024];
    unsigned char key[8], iv[8];  //其中key为对称密钥,iv为初始化向量。

    for (i = 0; i < 8; i++) {
        memset(&key[i], i + 1, 1);
        memset(&iv[i], i + 1, 1);
    }
    bc = BIO_new(BIO_f_cipher());
    BIO_set_cipher(bc, c, key, iv, 1);  //设置加密BI。
    b = BIO_new(BIO_s_null());
    b = BIO_push(bc, b);
    len = BIO_write(b, "openssl", 7);
    len = BIO_read(b, tmp, 1024);
    BIO_free(b);

    /* 解密 */
    BIO *bdec = NULL, *bd = NULL;
    const EVP_CIPHER* cd = EVP_des_ecb();
    bdec = BIO_new(BIO_f_cipher());
    BIO_set_cipher(bdec, cd, key, iv, 0);  //设置解密BIO。
    bd = BIO_new(BIO_s_null());
    bd = BIO_push(bdec, bd);
    len = BIO_write(bdec, tmp, len);
    len = BIO_read(bdec, tmp, 1024);
    BIO_free(bdec);
    return 0;
}
```

### 7.4.6 ssl BIO

```cpp
#include <openssl/bio.h>
#include <openssl/ssl.h>
int main() {
    BIO *sbio, *out;
    int len;
    char tmpbuf[1024];
    SSL_CTX* ctx;
    SSL* ssl;

    SSLeay_add_ssl_algorithms();
    OpenSSL_add_all_algorithms();
    ctx = SSL_CTX_new(SSLv3_client_method());
    sbio = BIO_new_ssl_connect(ctx);
    BIO_get_ssl(sbio, &ssl);
    if (!ssl) {
        fprintf(stderr, "Can not locate SSL pointer\n");
        return 0;
    }
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(sbio, "mybank.icbc.com.cn:https");
    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    BIO_printf(out,”链接中….\n”);
    if (BIO_do_connect(sbio) <= 0) {
        fprintf(stderr, "Error connecting to server\n");
        return 0;
    }
    if (BIO_do_handshake(sbio) <= 0) {
        fprintf(stderr, "Error establishing SSL connection\n");
        return 0;
    }
    BIO_puts(sbio, "GET / HTTP/1.0\n\n");
    for (;;) {
        len = BIO_read(sbio, tmpbuf, 1024);
        if (len <= 0)
            break;
        BIO_write(out, tmpbuf, len);
    }
    BIO_free_all(sbio);
    BIO_free(out);
    return 0;
}
```

​	本函数用ssl bio来链接mybank.icbc.com.cn的https服务，并请求首页文件。其中SSLeay_add_ssl_algorithms和OpenSSL_add_all_algorithms函数必不可少，否则不能找到ssl加密套件并且不能找到各种算法。

### 7.4.7 其他示例

```cpp
#include <openssl/asn1.h>
#include <openssl/bio.h>
int main() {
    int ret, len, indent;
    BIO* bp;
    char *pp, buf[5000];
    FILE* fp;

    bp = BIO_new(BIO_s_file());
    BIO_set_fp(bp, stdout, BIO_NOCLOSE);
    fp = fopen("der.cer", "rb");
    len = fread(buf, 1, 5000, fp);
    fclose(fp);
    pp = buf;
    indent = 5;
    ret = BIO_dump_indent(bp, pp, len, indent);
    BIO_free(bp);
    return 0;
}
```

