// SSH proxy: listen on :2222, forward to target, log all traffic hex
// Usage: ./ssh_proxy [host] [port] &  ssh -p 2222 user@localhost

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#define DEF_HOST "cnb.space"
#define DEF_PORT 22
#define LISTEN_PORT 2222
#define BUF_SIZE 65536

static volatile int running = 1;

void handle_sigint(int sig) { (void)sig; running = 0; }

void hexlog(const char*dir,const unsigned char*d,int l){
    printf("\n[%s] %d bytes:",dir,l);
    for(int i=0;i<l&&i<256;i++){if(i%16==0)printf("\n ");printf(" %02x",d[i]);}
    printf("\n");fflush(stdout);
}

int send_all(int s,const void*d,int l){
    int t=0;while(t<l){int n=send(s,(const char*)d+t,l-t,0);if(n<=0)return n;t+=n;}return t;
}

int main(int argc,char**argv){
    const char*host=argc>1?argv[1]:DEF_HOST;
    int port=argc>2?atoi(argv[2]):DEF_PORT;
    
    signal(SIGPIPE,SIG_IGN);
    signal(SIGINT,handle_sigint);
    
    int ls=socket(AF_INET,SOCK_STREAM,0);
    if(ls<0){perror("socket");return 1;}
    int opt=1;setsockopt(ls,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
    
    struct sockaddr_in addr={0};
    addr.sin_family=AF_INET;
    addr.sin_addr.s_addr=INADDR_ANY;
    addr.sin_port=htons(LISTEN_PORT);
    
    if(bind(ls,(struct sockaddr*)&addr,sizeof(addr))<0){perror("bind");return 1;}
    if(listen(ls,1)<0){perror("listen");return 1;}
    
    printf("Proxy: :%d -> %s:%d\n",LISTEN_PORT,host,port);
    fflush(stdout);
    
    while(running){
        int cs=accept(ls,NULL,NULL);
        if(cs<0)continue;
        printf("\n=== New client ===\n");
        
        // Connect to target  
        struct addrinfo hints={0},*res;
        hints.ai_family=AF_UNSPEC;hints.ai_socktype=SOCK_STREAM;
        char ps[16];snprintf(ps,sizeof(ps),"%d",port);
        if(getaddrinfo(host,ps,&hints,&res)!=0){close(cs);freeaddrinfo(res);continue;}
        
        int ts=socket(res->ai_family,res->ai_socktype,res->ai_protocol);
        if(ts<0||connect(ts,res->ai_addr,res->ai_addrlen)<0){close(cs);freeaddrinfo(res);continue;}
        freeaddrinfo(res);
        int f=1;setsockopt(ts,IPPROTO_TCP,TCP_NODELAY,&f,sizeof(f));
        setsockopt(cs,IPPROTO_TCP,TCP_NODELAY,&f,sizeof(f));
        
        printf("Connected to target\n");fflush(stdout);
        
        // Fork: child does bidirectional forwarding
        pid_t pid=fork();
        if(pid<0){close(cs);close(ts);continue;}
        if(pid==0){
            close(ls);
            fd_set rfds;
            while(running){
                FD_ZERO(&rfds);FD_SET(cs,&rfds);FD_SET(ts,&rfds);
                int mx=(cs>ts)?cs:ts;
                if(select(mx+1,&rfds,NULL,NULL,NULL)<=0)break;
                
                if(FD_ISSET(cs,&rfds)){
                    unsigned char buf[BUF_SIZE];
                    int n=recv(cs,buf,sizeof(buf),0);
                    if(n>0){hexlog("C->S",buf,n);send_all(ts,buf,n);}
                    else{printf("[C->S] done\n");shutdown(ts,SHUT_WR);}
                }
                
                if(FD_ISSET(ts,&rfds)){
                    unsigned char buf[BUF_SIZE];
                    int n=recv(ts,buf,sizeof(buf),0);
                    if(n>0){hexlog("S->C",buf,n);send_all(cs,buf,n);}
                    else{printf("[S->C] done\n");shutdown(cs,SHUT_WR);}
                }
            }
            exit(0);
        }
        close(cs);close(ts);
    }
    return 0;
}
