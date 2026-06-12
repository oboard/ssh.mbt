ssh 是 docker 运行的，已经在运行了，ssh 服务是使用密码验证的，密码是 123456

使用 ssh 客户端，可以正常使用 
➜  /workspace git:(master) ✗ ssh admin@127.0.0.1 -p 1022
admin@127.0.0.1's password: 
Welcome to OpenSSH Server
d1a3b3666350:~$ 


要求：
0. 先整体阅读项目，这个是一个 moon 实现的 ssh 客户端项目
1. 不要使用 git 查看历史记录
2. 只使用 run.sh 编译 并 运行
3. 查看 run.sh 运行结果，参考 ssh 标准协议 修复问题
4. 不使用 python 等其他工具，只需要对照 ssh 协议修复，查看流程是否符合，加密方法是否符合
5. 添加更多协议的 log 调试查看输出
6. 现在运行 run.sh 输出

/root/.moon/lib/core/abort/abort.mbt:50 at @moonbitlang/core/abort.abort[Unit]
/workspace/cmd/main/main.mbt:17 by main
read_plain: pkt_len=1036
Server KEX algorithms: [mlkem768x25519-sha256, sntrup761x25519-sha512, sntrup761x25519-sha512@openssh.com, curve25519-sha256, curve25519-sha256@libssh.org, ecdh-sha2-nistp256, ecdh-sha2-nistp384, ecdh-sha2-nistp521, ext-info-s, kex-strict-s-v00@openssh.com]
Server host key algs: [ecdsa-sha2-nistp256, ssh-ed25519, rsa-sha2-512, rsa-sha2-256]
Server enc algorithms: [chacha20-poly1305@openssh.com, aes128-gcm@openssh.com, aes256-gcm@openssh.com, aes128-ctr, aes192-ctr, aes256-ctr]
Server mac algorithms: [umac-64-etm@openssh.com, umac-128-etm@openssh.com, hmac-sha2-256-etm@openssh.com, hmac-sha2-512-etm@openssh.com, hmac-sha1-etm@openssh.com, umac-64@openssh.com, umac-128@openssh.com, hmac-sha2-256, hmac-sha2-512, hmac-sha1]
Negotiated kex_alg: ecdh-sha2-nistp256
Negotiated host_key_alg: rsa-sha2-256
Negotiated enc: aes128-ctr mac: hmac-sha2-256
drive_ecdh: about to read ECDH_REPLY...
kex: IoError(read packet: PaiGack/ssh_client/src/socket.IoError.IoError)
➜  /workspace git:(main) ✗ 

