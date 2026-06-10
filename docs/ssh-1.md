SSH客户端的实现1 加密通信的建立
目的
ssh是研发的必用工具，有必要了解其工作原理和学习其相关知识。

主要任务是调通总体流程，实现一个简单的客户端。

细节上肯定问题，且不通用。暂且不去纠结。

环境
测试服务器ssh版本是SSH-2.0-OpenSSH_8.2p1 Ubuntu-4。

key交换算法用diffie-hellman-group-exchange-sha256

加密算法用aes256-ctr

mac算法用hmac-sha2-256

公钥算法用ssh-rsa

用python3编码

加密库用 https://cryptography.io/en/latest/

gui库用 https://github.com/hoffstadt/DearPyGui

介绍
The Secure Shell (SSH) Protocol Architecture

https://www.rfc-editor.org/rfc/rfc4251

rfc4251为ssh协议的整体描述 ssh协议分为三部分

传输协议 Transport Layer Protocol 提供传输的保密性、完整性、压缩。一般运行在tcp/ip之上。

鉴权协议 User Authentication Protocol 对连上ssh服务的客户端进行鉴权。运行在传输协议之上。

连接协议 Connection Protocol 把加密通道分为多个逻辑通道。运行在鉴权协议之上。

整体架构
host key
服务端必须有一个host key。用与在key交换的过程中确保client连上的是正确的server。 而client必须事先知道这个key。

两种信任模式：

client维护一套host和key的对应 这种方法不需要第三方介入。但需要花资源维护数据。

host key由CA验证 client只需记住CA的root key，通过CA来验证server的host key。

第二种解决了维护问题，

扩展性
技术、协议、算法是会不断进化，目前rfc只规定最简的架构和算法，必须保证可扩展性。

策略
ssh协议允许下列事项的自由协商：加密、完整性、key交换、压缩、public key算法和各种格式。

下列事项需要在实现时进行确定：

两个方向的加密、完整性和压缩算法

public key算法和key交换方法。

认证算法

用户在连接协议之上可进行的操作。

安全属性
ssh协议的一个主要目的就是让网络更安全。

所用加密、完整性、public key算法必须是知名、经过考验的算法。

对于使用了较安全的key长度的算法，有能力抵御几十年的攻击。

所有算法都是可协商的。如果某个算法爆出问题，可以轻易替换为其他算法，而不用改基础协议。

本地化和字符集支持
很难统一。应尽量指定字符集。一般需支持utf8。

ssh协议里的数据类型
byte
8位数据。byte[n]表示n个字节。

boolean
一个byte。0为false，1为true。

uint32
32位无符号整数。按network byte order即大端存，即0x29b7f4aa存为29 b7 f4 aa。

uint64
64位无符号整数。

string
任意长度字符串。开头用一个uint32表示后续字符串的长度n。接着是n个byte。 可按需用ascii或utf8等编码

mpint
用2的补码形式表示的多精度整数。 整个数据是一个string，即开头是一个uint32指定后续数据长度。 如果是负数，数据部分的第一位必须是1。（见下面的-1234） 如果一个整数的第一位是1，那么需要在开头加个0，来和负数区分。（见下面的80）

value (hex)        representation (hex)
-----------        --------------------
0                  00 00 00 00
9a378f9b2e332a7    00 00 00 08 09 a3 78 f9 b2 e3 32 a7
80                 00 00 00 02 00 80
-1234              00 00 00 02 ed cc
-deadbeef          00 00 00 05 ff 21 52 41 11
bin(0xedcc) 0b1110 1101 1100 1100 取反 0b0001 0010 0011 0011 +1 0b0001 0010 0011 0100 hex为1234。加上负号即为-0x1234。

name-list
用,号隔开的字符串列表。每个字符串长度必须大于0，不能包含,号。 只能包含ascii。第一个uint32为后续总长度。

value                      representation (hex)
-----                      --------------------
(), the empty name-list    00 00 00 00
("zlib")                   00 00 00 04 7a 6c 69 62
("zlib,none")              00 00 00 09 7a 6c 69 62 2c 6e 6f 6e 65
消息编号
https://www.rfc-editor.org/rfc/rfc4250#section-4.1.1

传输层协议
1-19 传输层常用(比如disconnect, ignore, debug等)
20-29 算法协商
30-49 key交换方法

用户鉴权协议
50-59 通用
60-79 特定

连接协议
80-89 通用
90-127 通道相关

为client保留
128-191

本地扩展
192-255

Binary Packet Protocol ssh的数据包格式
https://www.rfc-editor.org/rfc/rfc4253#section-6

uint32 数据包总长度
byte 填充长度
byte[n1] payload。 n1 = 数据包总长度 - 填充长度 - 1
byte[n2] 随机填充数据。 n2 = 填充长度
byte[m] mac(Message Authentication Code)。 
最大长度

必须能处理不压缩的长度为32768的payload。

压缩

如果协商了启用压缩。将会对payload进行压缩。

加密

加密算法和密钥会在密钥交换过程中协商好。 如果启用加密。包的总长度、填充长度、payload、填充数据都会进行加密。

完整性

每次对数据包算一个mac(Message Authentication Code)来保证完整性。

Public Key Algorithms 公钥算法
暂且忽略

Diffie-Hellman key交换算法
https://www.rfc-editor.org/rfc/rfc4419
https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
https://en.wikipedia.org/wiki/Discrete_logarithm
https://zh.wikipedia.org/wiki/%E7%A6%BB%E6%95%A3%E5%AF%B9%E6%95%B0

用来在没有一个安全通道的情况下，在两端生成一个公用的secret。

必须两端共同参与生成，无法由单独一端生成。

secret只有这两端知道，即使交换过程被监听也很难被破解。

后续两端在这个secret的基础上加密通信数据。

离散对数问题
对于 e = g^x mod p p是一个很大的质数，比如1024bit。 从g、x、p可以快速算出e。 但从已知的e、g、p，很难求得x。

Diffie-Hellman key交换算法的安全性就是基于这个难题。 很多密码学的组件都是基于离散对数问题。

key交换算法最后产出一个公共的密钥K和一个hash值H。 之后加密和授权等会依赖这两个值。

变量定义
p 大质数
g generator
min client可接受的最小的p的位数
n client希望的p的位数
max client可接受的最大的p的位数
V_S server的版本信息
V_C client的版本信息
K_S server的public host key数据
I_C client的KEXINIT消息
I_S server的KEXINIT消息
流程
1.client发key交换请求
byte SSH_MSG_KEY_DH_GEX_REQUEST
uint32  min
uint32  n
uint32  max
比如min、n、max我都取2048。

2. server找最匹配的group
server需要存一批精心挑选的通用的安全质数(safe primes)p和各自对应的generator g。

见 https://www.rfc-editor.org/rfc/rfc3526

我们client传了2048，那么会找到2048bit的group。

https://www.rfc-editor.org/rfc/rfc3526

This group is assigned id 14.

   This prime is: 2^2048 - 2^1984 - 1 + 2^64 * { [2^1918 pi] + 124476 }

   Its hexadecimal value is:

      FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
      670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
      E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
      DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
      15728E5A 8AACAA68 FFFFFFFF FFFFFFFF

   The generator is: 2.
那么p值就是那一大串hex。g就是2。

server发确定的p和g

byte    SSH_MSG_KEX_DH_GEX_GROUP
mpint   p
mpint   g
3. client计算e
client生成一个随机数x。1 < x < (p-1)/2。

e = g^x mod p 比如 e = pow(2, 666666666666666666, p) pow必须加mod参数。也必须加mod限定，才能快速算出可行的结果。

client发

byte    SSH_MSG_KEX_DH_GEX_INIT
mpint   e
这里想一下，client发数据时，e、g、p都是在网络上可见的，是不安全的，但是因为离散对数难题，x可以认为是无法破解的。

4. server
server生成一个随机数y。1 < y < (p-1)/2。 f = g^y mod p

K = e^y mod p K即为双方共同生成的key。这里是基于取模运算的性质的，后续会说明。

H = hash(V_C || V_S || I_C || I_S || K_S || min || n || max || p || g || e || f || K) 用私钥对H签名得到s

我们用的是diffie-hellman-group-exchange-sha256。 所以hash函数就是sha256

hash内容的格式

string  V_C, the client's version string (CR and NL excluded)
string  V_S, the server's version string (CR and NL excluded)
string  I_C, the payload of the client's SSH_MSG_KEXINIT
string  I_S, the payload of the server's SSH_MSG_KEXINIT
string  K_S, the host key
uint32  min, minimal size in bits of an acceptable group
uint32  n, preferred size in bits of the group the server will send
uint32  max, maximal size in bits of an acceptable group
mpint   p, safe prime
mpint   g, generator for subgroup
mpint   e, exchange value sent by the client
mpint   f, exchange value sent by the server
mpint   K, the shared secret
server发送

byte    SSH_MSG_KEX_DH_GEX_REPLY
string  K_S
mpint   f
string  s
5. client
client校验K_S，确保是server合法的host key。也可以不校验，但是有风险。

解析server的host key https://www.rfc-editor.org/rfc/rfc4253#section-6.6

K = f^x mod p

H = hash(V_C || V_S || I_C || I_S || K_S || min || n || max || p || g || e || f || K) 验证签名s

到此两端得到了相同的key K。

为什么两边会得到同一个key
x是client的随机数，y是server的随机数。

基于取模运算的性质： server算得的 K = (g^x mod p)^y mod p = g^(xy) mod p client算得的 K = (g^y mod p)^x mod p = g^(yx) mod p

所以两端利用离散对数难题把包含x和y的数据发给对方，即使中途被窃听也解不出x和y。 两端并不用解出对方的随机数，而是利用取模运算的性质，非常巧妙地达成了一致。

数据包的加密和完整性
key交换完成后。通信数据都要加密，并且验证完整性。

我们用aes256-ctr加密，32字节的key，加密block长度为16字节，模式为ctr。
按文档，必须把数据填充成长度为block长度和8之间大的那个数的倍数。这里就定为16字节的倍数。
https://www.rfc-editor.org/rfc/rfc4253#section-6

先正常拼数据

uint32 数据包总长度
byte 填充长度
byte[n1] payload。 n1 = 数据包总长度 - 填充长度 - 1
byte[n2] 随机填充数据。 n2 = 填充长度
得到未加密的数据包，包含padding。总长度为16的倍数。

再用mac key对[消息sn+未加密的数据包]算一个mac，附在数据包后面。 每发一个包，sn+1。从0开始，达到2^32归零。 mac = MAC(mac_key, sn || 未加密的数据包) sn为uint32

mac_key用公共密钥算。跟加密key相似。 https://www.rfc-editor.org/rfc/rfc4253#section-7.2 Integrity key client to server: HASH(K || H || "E" || session_id) mac算法选择hmac-sha2-256，生成一个32字节的hash。

session_id为第一次算得的H值。即使后续重新交换key，也不变。

再用加密key对数据包加密。

最后发给server的数据为[加密后的数据块+mac]。

解析server数据时以反方向操作即可。

数据包的边界问题
tcp可能出现一个ssh数据包分批到达socket接口，或者socket接收时收到不止一个完整的包。 需要定包边界。

不加密时，前4字节一定是包的长度，没有问题。

加密后其实也没问题。 aes的ctr模式是分块独立加密，这样每次解析新数据包时可以先读16字节解密，作为头。
头的前4字节是包的长度，这样包的边界实际也是定好的。
每个新包先读16字节，解密。再读剩下的包长度。最后读mac数据即可(mac长度是根据算法定死的32)。

总体流程
1. 交换协议版本
https://www.rfc-editor.org/rfc/rfc4253#section-4.2 两端互发包含协议版本等信息的字符串

server端的版本是 SSH-2.0-OpenSSH_8.2p1 Ubuntu-4\r\n

client端的版本是 SSH-2.0-WTFFFFFF\r\n 类似版本

2. 算法协商
https://www.rfc-editor.org/rfc/rfc4253#section-7.1 两端互发支持的算法

byte         SSH_MSG_KEXINIT
byte[16]     cookie (random bytes)
name-list    kex_algorithms
name-list    server_host_key_algorithms
name-list    encryption_algorithms_client_to_server
name-list    encryption_algorithms_server_to_client
name-list    mac_algorithms_client_to_server
name-list    mac_algorithms_server_to_client
name-list    compression_algorithms_client_to_server
name-list    compression_algorithms_server_to_client
name-list    languages_client_to_server
name-list    languages_server_to_client
boolean      first_kex_packet_follows
uint32       0 (reserved for future extension)
kex_algorithms 列出key交换算法

server_host_key_algorithms host key算法

encryption_algorithms 加密算法

mac_algorithms mac算法

compression_algorithms 压缩算法

都是左边优先，如果两边一个都匹配不到。断开连接。 因为算法是会进化的，所以新的server不一定支持老的客户端。算法匹配不了，server就会主动断开连接。

3. Diffie-Hellman Group Exchange 生成密钥
见上述算法流程。

结束后两端互发一个 SSH_MSG_NEWKEYS 表示key已经生成，以后都得用新的key和算法进行加密交互。

key不是直接用dh算法生成的K。而是要算hash值的。

https://www.rfc-editor.org/rfc/rfc4253#section-7.2

Encryption key client to server: HASH(K || H || "C" || session_id)

这一条就是client发数据给server要用的加密key，用sha256算出最终的32字节hash值。

4. client请求服务
https://www.rfc-editor.org/rfc/rfc4253#section-10

key交换完毕，client请求auth服务。

https://www.rfc-editor.org/rfc/rfc4252

client发

byte      SSH_MSG_SERVICE_REQUEST
string    "ssh-userauth"
4.1 aes加密
根据 https://www.rfc-editor.org/rfc/rfc4253#section-7.2 必须算出自己方向的加密iv、加密key和mac key。

选择aes256-ctr。aes256需要32字节的key，aes128需要16字节的key。

因为密钥选择使用sha256计算，有32字节。所以如果加密算法选的aes128，就得传密钥的前16字节。

这种输入输出长度都得搞清楚，否则server会直接断开。

可自己起ssd服务sshd -ddd来debug。一般加解密出问题会报bad packet length。mac出问题会报 mac corrupted。

5. server接受服务请求
server端收到client的数据，进行解密和mac验证。通过后发：

byte      SSH_MSG_SERVICE_ACCEPT
string    service name
client同样进行解密和mac验证。 都通过后两端即建立起了基本的加密通信通道。

参考
https://www.rfc-editor.org/rfc/rfc4250
https://www.rfc-editor.org/rfc/rfc4251
https://www.rfc-editor.org/rfc/rfc4252
https://www.rfc-editor.org/rfc/rfc4253
https://www.rfc-editor.org/rfc/rfc4254
https://www.rfc-editor.org/rfc/rfc3526
https://www.rfc-editor.org/rfc/rfc4419
https://www.openssh.com/
https://www.paramiko.org/
https://cryptography.io/en/latest

 On this page
目的
环境
介绍
整体架构
ssh协议里的数据类型
消息编号
Binary Packet Protocol ssh的数据包格式
Public Key Algorithms 公钥算法
Diffie-Hellman key交换算法
数据包的加密和完整性
总体流程
1. 交换协议版本
2. 算法协商
3. Diffie-Hellman Group Exchange 生成密钥
4. client请求服务
4.1 aes加密
5. server接受服务请求