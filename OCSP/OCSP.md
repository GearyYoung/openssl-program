# 第二十七章 OCSP

## 27.1  概述

​	在线证书状态协议（OCSP，Online Certificate Status Protocol，rfc2560）用于实时表明证书状态。OCSP客户端通过查询OCSP服务来确定一个证书的状态。OCSP可以通过HTTP协议来实现。rfc2560定义了OCSP客户端和服务端的消息格式。

## 27.2  openssl实现

​	openssl在crypto/ocsp目录实现了ocsp模块，包括客户端和服务端各种函数。主要源码如下：

* ocsp_asn.c：ocsp消息的DER编解码实现，包括基本的new、free、i2d和d2i函数；
* ocsp_cl.c：ocsp客户端函数实现，主要用于生成ocsp请求；
* ocsp_srv.c：ocsp服务端思想，主要用于生成ocsp响应；
* ocsp_err.c：ocsp错误处理；
* ocsp_ext.c：ocsp扩展项处理；
* ocsp_ht.c：基于HTTP协议通信的OCSP实现；
* ocsp_lib.c：通用库实现；
* ocsp_prn：打印OCSP信息；
* ocsp_vfy：验证ocsp请求和响应；
* ocsp.h：定义了ocsp请求和响应的各种数据结构和用户接口。

## 27.3  主要函数

1. `d2i_OCSP_REQUEST_bio`
   将bio中的DER编码的数据转换为OCSP_REQUEST数据结构。
2. `d2i_OCSP_RESPONSE_bio`
   将bio中的DER编码的数据转换为OCSP_RESPONSE数据结构。
3. `i2d_OCSP_RESPONSE_bio`
   将OCSP_RESPONSE数据结构DER编码，并输出到BIO中。
4. `i2d_OCSP_REQUEST_bio`
   将OCSP_REQUEST数据结构DER编码，并输出到BIO中。
5. `PEM_read_bio_OCSP_REQUEST`
   读取PEM格式的OCSP_REQUEST信息，返回其数据结构。
6. `PEM_read_bio_OCSP_RESPONSE`
   读取PEM格式的OCSP_RESPONSE信息，返回其数据结构。
7. `PEM_write_bio_OCSP_REQUEST`
   将OCSP_REQUEST结构写成PEM格式。
8. `PEM_write_bio_OCSP_RESPONSE`
   将OCSP_RESPONSE结构写成PEM格式。
9. `OCSP_REQUEST_sign`
   本函数由宏来定义，它用于给OCSP_REQUEST数据结构签名。签名的对象为DER编码的OCSP_REQINFO信息，签名算法为OCSP_SIGNATURE指定的的算法，签名私钥以及摘要算法由输入参数指定。
10. `int OCSP_request_sign(OCSP_REQUEST *req, X509 *signer,EVP_PKEY *key,const EVP_MD *dgst,STACK_OF(X509) *certs,unsigned long flags)`
   本函数用于给OCSP请求消息签名，通过OCSP_REQUEST_sign函数进行签名，将signer持有者信息写入req，如果flags不为OCSP_NOCERTS，将certs信息写入req。
11. `OCSP_BASICRESP_sign`
   对OCSP_BASICRESP结构进行签名，签名结果放在OCSP_BASICRESP的signature中，摘要算法由输入参数指定。
12. `OCSP_REQUEST_verify`
   验证ocsp请求签名，公钥由输入参数指定。
13. `OCSP_BASICRESP_verify`
   验证ocsp响应签名，公钥由输入参数指定。
14. `OCSP_request_verify`
   验证ocsp响应，该函数做全面的验证，包括签名、证书目的以及证书链等。
15. `int OCSP_basic_sign(OCSP_BASICRESP *brsp,X509 *signer, EVP_PKEY *key,const EVP_MD *dgst,STACK_OF(X509) *certs, unsigned long flags)`
   本函数用输入参数signer、key、dgst、certs和flags来填充brsp数据结构，并对brsp结构签名，成功返回1，否则返回0。
16. `int OCSP_check_validity(ASN1_GENERALIZEDTIME *thisupd, ASN1_GENERALIZEDTIME *nextupd, long nsec, long maxsec)`
   时间检查计算，合法返回1，thisupd为本次更新时间，nextupd为下次更新时间。thisupd和nextupd由响应服务生成，他们被传给请求者。请求者收到响应之后需要验证ocsp消息的时间有效性。要求如下：
* 本次更新时间不能比当前时间提前太多，提前时间不能大于nsec，比如ocsp服务器多时间比请求者系统时间快很多，导致thisupd错误非法；
* 本次更新时间不能晚于当前时间太多，否则ocsp消息失效，晚的时间不能大于maxsec；
* 下次更新时间不能晚于当前时间太多，晚多时间不大于nsec(由于下一条规则限制，也不能大于maxsec)；
* 下次更新时间必须大于本次更新时间。
  总之，本次更新时间和下次更新时间必须在以当前时间为中心的一个窗口内。
17. `OCSP_CERTID_dup`
    复制函数。
18. `OCSP_CERTSTATUS_dup`
    复制函数。
19. `OCSP_ONEREQ *OCSP_request_add0_id(OCSP_REQUEST *req,OCSP_CERTID *cid)`
    本函数用于往请求消息中添加一个证书ID；它将一个OCSP_CERTID信息存入OCSP_REQUEST结构，返回内部生成的OCSP_ONEREQ指针。根据cid构造一个OCSP_ONEREQ信息，并将此信息放入req请求消息的堆栈。
20. `int OCSP_request_set1_name(OCSP_REQUEST *req, X509_NAME *nm)`
    本函数用于设置消息请求者的名字。
21. `int OCSP_request_add1_cert(OCSP_REQUEST *req, X509 *cert)`
    本函数往消息请求中添加一个证书。此证书信息放在OCSP_REQUEST结构的一个堆栈中，并将此证书结构的引用加1。
22. `int OCSP_response_status(OCSP_RESPONSE *resp)`
    本函数获取OCSP响应状态。
23. `OCSP_BASICRESP *OCSP_response_get1_basic(OCSP_RESPONSE *resp)`
    本函数从响应数据结构中获取OCSP_BASICRESP信息。
24. `int OCSP_resp_count(OCSP_BASICRESP *bs)`
    本函数获取响应消息中包含的证书状态的个数。
25. `OCSP_SINGLERESP *OCSP_resp_get0(OCSP_BASICRESP *bs, int idx)`
    给定单个响应的序号，从堆栈中取出。
26. `int OCSP_resp_find(OCSP_BASICRESP *bs, OCSP_CERTID *id, int last)`
    根据ocsp证书ID查询对应的响应在堆栈中的位置，last为搜索堆栈时的起始位置，如果小于0，从0开始。
27. `int OCSP_single_get0_status(OCSP_SINGLERESP *single, int *reason,ASN1_GENERALIZEDTIME **revtime,ASN1_GENERALIZEDTIME **thisupd,ASN1_GENERALIZEDTIME **nextupd)`
    获取单个证书的状态，返回值为其状态，ocsp.h中定义如下：
```
#define V_OCSP_CERTSTATUS_GOOD 0
#define V_OCSP_CERTSTATUS_REVOKED 1
#define V_OCSP_CERTSTATUS_UNKNOWN 2
#define V_OCSP_CERTSTATUS_GOOD 0
#define V_OCSP_CERTSTATUS_REVOKED 1
#define V_OCSP_CERTSTATUS_UNKNOWN 2
```
如果证书被撤销，并且reason和revtime参数不为空，将撤销原因以及撤销时间返回。并且对于这个证书给出thisUpdate和nextUpdate。
28. `int OCSP_resp_find_status(OCSP_BASICRESP *bs, OCSP_CERTID *id, int *status,int *reason,ASN1_GENERALIZEDTIME **revtime,ASN1_GENERALIZEDTIME **thisupd,ASN1_GENERALIZEDTIME **nextupd)`
    功能同OCSP_single_get0_status函数，id为OCSP证书ID，它依次调用OCSP_resp_find、OCSP_resp_get0和 OCSP_single_get0_status函数，其中status为返回的证书状态。
29. `int OCSP_request_add1_nonce(OCSP_REQUEST *req, unsigned char *val, int len)`
    添加nonce扩展项,val和len表明了nonce值,如果val为空,则内部生成长度为len的随机数作为nonce。
30. `int OCSP_basic_add1_nonce(OCSP_BASICRESP *resp, unsigned char *val, int len)`
    功能同上。
31. `int OCSP_check_nonce(OCSP_REQUEST *req, OCSP_BASICRESP *bs)`
    检测nonce，用于防止重放攻击；检查请求和响应的nonce扩展项，看他们是否相等，OCSP服务端应当将请求中的nonce拷贝到响应中。如果请求和响应中的nonce扩展项都存在，比较nonce值，如果不相等，返回错误，或者，请求中有nonce，而响应中没有nonce，也返回错误。验证正确时返回值大于0。
32. `int OCSP_copy_nonce(OCSP_BASICRESP *resp, OCSP_REQUEST *req)`
    将请求中都nonce拷贝到响应中。
33. `X509_EXTENSION *OCSP_crlID_new(char *url, long *n, char *tim)`
    根据crl的url，crl个数以及生成crl的时间生成X509_EXTENSION扩展项。
34. `X509_EXTENSION *OCSP_accept_responses_new(char **oids)`
    根据多个oid的名字生成扩展项，其中oids指针数组，以NULL结尾。本函数由客户端调用，告诉服务端它所要的端响应的类型，参考rfc2560对于AcceptableResponses扩展项的说明。
35. `X509_EXTENSION *OCSP_archive_cutoff_new(char* tim)`
    生成单个证书的Archive Cutoff扩展项，某已被撤销的证书的Archive Cutoff时间为本次OCSP生效时间(producedAt)减去被撤销时的时间。可以将它看作已撤销了多长时间。
36. `X509_EXTENSION *OCSP_url_svcloc_new(X509_NAME* issuer, char **urls)`
    根据颁发者名字和一个或多个url生成扩展项。扩展项内容为AuthorityInfoAccess。urls为指针数组，以NULL结束。
37. `OCSP_CERTID *OCSP_cert_to_id(const EVP_MD *dgst, X509 *subject, X509 *issuer)`
    根据摘要算法、持有者证书和颁发者证书生成OCSP_CERTID数据结构。
38. `OCSP_CERTID *OCSP_cert_id_new(const EVP_MD *dgst,X509_NAME *issuerName,ASN1_BIT_STRING* issuerKey,ASN1_INTEGER *serialNumber)`
    本函数根据摘要算法、颁发者名字、颁发者公钥DER编码以及证书持有者的证书序列号生成OCSP_CERTID；奇怪的是serialNumber可以为空，无法标识需要查询状态证书。
39. `int OCSP_id_issuer_cmp(OCSP_CERTID *a, OCSP_CERTID *b)`
    比较OCSP_CERTID，如果相等返回0，不相等返回非0。本函数不比较证书序列号。
    40）int OCSP_id_cmp(OCSP_CERTID *a, OCSP_CERTID *b)

比较OCSP_CERTID，如果相等返回0，不相等返回非0。本函数比较所有项，包括证书序列号。

41. `int OCSP_parse_url(char *url, char **phost, char **pport, char **ppath, int *pssl)`
    分析url，获取主机、端口、路径和协议(http还是https)等信息。
42. `char *OCSP_response_status_str(long s)`
    根据OCSP响应码获取响应状态信息。
43. `char *OCSP_cert_status_str(long s)`
    根据证书状态码获取证书状态信息。
44. `char *OCSP_crl_reason_str(long s)`
    根据状态码获取证书撤销原因。
45. `int OCSP_REQUEST_print(BIO *bp, OCSP_REQUEST* o, unsigned long flags)`
    将OCSP请求OCSP_REQUEST的信息输出到bp中,flags表明不支持到扩展项 的处理方式，参考X509V3_extensions_print以及X509V3_EXT_print函数。
46. `int OCSP_RESPONSE_print(BIO *bp, OCSP_RESPONSE* o, unsigned long flags)`
    将OCSP请求OCSP_RESPONSE的信息输出到bp中,flags表明不支持到扩展项到处理方式,参考X509V3_extensions_print以及X509V3_EXT_print   函数。
47. `int OCSP_request_onereq_count(OCSP_REQUEST *req)`
    获取OCSP请求中请求列表的个数,即多少个证书状态需要查询。
48. `OCSP_ONEREQ *OCSP_request_onereq_get0(OCSP_REQUEST *req, int i)`
    根据在堆栈中到位置获取OCSP_ONEREQ,OCSP_ONEREQ包含了单个证书的信息。
49. `OCSP_CERTID *OCSP_onereq_get0_id(OCSP_ONEREQ *one)`
    获取OCSP_ONEREQ中到证书ID信息。
50. `int OCSP_id_get0_info(ASN1_OCTET_STRING **piNameHash,ASN1_OBJECT **pmd,ASN1_OCTET_STRING **pikeyHash,ASN1_INTEGER **pserial, OCSP_CERTID *cid)`
    从cid中获取颁发者名字摘要值、摘要算法、颁发者公钥摘要值以及持有者证书序列号,成功返回1,否则为0。
51. `int OCSP_request_is_signed(OCSP_REQUEST *req)`
    判断请求是否已签名，如果已签名返回1,否则返回0。
52. `OCSP_RESPONSE *OCSP_response_create(int status, OCSP_BASICRESP *bs)`
    生成OCSP响应数据，status为响应状态，bs为响应的具体内容。
53. `OCSP_SINGLERESP *OCSP_basic_add1_status(OCSP_BASICRESP *rsp,OCSP_CERTID *cid,int status, int reason,ASN1_TIME *revtime,ASN1_TIME *thisupd, ASN1_TIME *nextupd)`
    根据输入参数证书ID、证书状态、撤销原因、撤销时间、本次OCSP时间以及下次OCSP时间生成一个单一证书的状态信息，将此状态信息放入rsp的堆栈中，并返回此状态信息。
54. `int OCSP_basic_add1_cert(OCSP_BASICRESP* resp, X509* cert)`
    添加一个证书到响应信息中。
55. `ASN1_STRING *ASN1_STRING_encode(ASN1_STRING* s, i2d_of_void* i2d, void* data, STACK_OF(ASN1_OBJECT) * sk)`
    本函数将数据进行DER编码,编码后的结果放在ASN1_STRING中，并返回此ASN1_STRING。其中，s为要设置的ASN1_STRING，i2d为输入数据的i2d方法,data为输入数据结构，sk为输入对象堆栈。如果data不为空，则DER编码data指向的数据结构；如果data为空，sk不为空，则DER编码sk堆栈表示的内容。
56. `int OCSP_REQUEST_get_ext_count(OCSP_REQUEST* x)`
    获取OCSP_REQUEST结构中tbsRequest成员的扩展项的个数。
57. `int OCSP_REQUEST_get_ext_by_NID(OCSP_REQUEST* x, int nid, int lastpos)`
    根据对象nid获取扩展项在x->tbsRequest->requestExtensions中的位置。
58. `int OCSP_REQUEST_get_ext_by_OBJ(OCSP_REQUEST* x,ASN1_OBJECT* obj,int lastpos)`
    获取对象在x->tbsRequest->requestExtensions中的位置。
59. `int OCSP_REQUEST_get_ext_by_critical(OCSP_REQUEST* x, int crit, int lastpos)`
    根据是否关键crit以及堆栈搜索基准lastpos获取x->tbsRequest->requestExtensions中扩展项的位置。
60. `X509_EXTENSION *OCSP_REQUEST_get_ext(OCSP_REQUEST* x, int loc)`
    根据扩展项在堆栈中的位置获取扩展项。
61. `X509_EXTENSION *OCSP_REQUEST_delete_ext(OCSP_REQUEST* x, int loc)`
    根据扩展项在堆栈中的位置删除扩展项。
62. `void *OCSP_REQUEST_get1_ext_d2i(OCSP_REQUEST* x, int nid, int* crit, int* idx)`
    根据扩展项nid获取扩展项信息，其中返回值为扩展项数据结构的指针地址，crit返回是否时关键扩展，idx表明它在堆栈中的位置。
63. `int OCSP_REQUEST_add1_ext_i2d(OCSP_REQUEST* x, int nid, void* value, int crit,unsigned long flags)` 
    将具体的扩展项添加到x中，成功则返回1。其中，nid表明是什么扩展项，crit表明是否是关键扩展，value是具体扩展项数据结构的地址，flags表明了何种操作，参考函数X509V3_add1_i2d。
64. `int OCSP_REQUEST_add_ext(OCSP_REQUEST* x, X509_EXTENSION* ex,int loc)`
    将扩展项添加到x->tbsRequest->requestExtensions堆栈中,loc表示堆栈位置。
65. `int OCSP_basic_verify(OCSP_BASICRESP* bs, STACK_OF(X509) * certs,X509_STORE* st,unsigned long flags)`
    验证OCSP响应消息,成功返回1。验证内容有：验证OCSP签名、验证签名者证书、检查每个证书状态信息的颁发者是否是相同、检查颁发者证书的扩展密钥用法中是否支持OCSP签名。

## 27.4编程示例

ocsp的编程主要是生成ocsp请求、解析ocsp请求、生成ocsp响应、解析ocsp响应得到结果以及消息的签名和验证。客户端可用ocsp_cl.c中提供的函数，服务端可用ocsp_srv.c中提供的函数。典型的应用程序请参考apps/ocsp.c。