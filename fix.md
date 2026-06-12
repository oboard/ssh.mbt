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
➜  /workspace git:(main) ✗ 
