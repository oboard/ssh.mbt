#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

void p32(unsigned char*p,uint32_t v){p[0]=v>>24;p[1]=v>>16;p[2]=v>>8;p[3]=v;}
int anl(unsigned char*b,int o,const char*s){int l=strlen(s);p32(b+o,l);memcpy(b+o+4,s,l);return o+4+l;}
void hd(const char*lab,const unsigned char*d,int l){
    printf("%s (%dB):\n",lab,l);fflush(stdout);
    for(int i=0;i<l;i++){printf("%02x ",d[i]);if(i%15==14){printf("\n");fflush(stdout);}}
    if(l%16!=0){printf("\n");fflush(stdout);}
}
#define LOG(...) do{printf(__VA_ARGS__);fflush(stdout);}while(0)

static int tx(int s,const void*d,int l){int t=0;while(t<l){int n=send(s,(const char*)d+t,l-t,0);if(n<0)return-1;if(n==0)continue;t+=n;}return t;}

int ctcp(const char*h,int p){
    struct addrinfo hints={0},*res;
    hints.ai_family=AF_UNSPEC;hints.ai_socktype=SOCK_STREAM;
    char ps[16];snprintf(ps,sizeof(ps),"%d",p);
    if(getaddrinfo(h,ps,&hints,&res))return-1;
    int s=socket(res->ai_family,res->ai_socktype,res->ai_protocol);
    if(s<0)return-1;
    int f=1;setsockopt(s,IPPROTO_TCP,TCP_NODELAY,&f,4);
    if(connect(s,res->ai_addr,res->ai_addrlen)<0){close(s);freeaddrinfo(res);return-1;}
    freeaddrinfo(res);return s;
}

int main(){
    setbuf(stdout,NULL);
    LOG("=== Full SSH KEX test mimicking OpenSSH ===\n");
    
    int sock=ctcp("cnb.space",22);
    if(sock<0){LOG("Connect failed\n");return 1;}

    // Read server banner byte by byte
    unsigned char buf[8192];
    int bl=0;
    while(bl<8191){
        int n=recv(sock,buf+bl,1,0);
        if(n<=0){close(sock);LOG("Banner recv failed\n");return 1;}
        if(buf[bl]=='\n')break;
        bl++;
    }
    buf[bl]=0;
    LOG("Server: [%s] bl=%d last_char=0x%02x\n",(char*)buf,bl,bl>0?buf[bl-1]:0);

    // Send client banner
    LOG("Sending banner...\n");
    tx(sock,"SSH-2.0-OpenSSH_10.0\r\n",21);
    LOG("Banner sent, waiting...\n");
    usleep(200000);
    
    // Read server KEXINIT
    LOG("Reading server KEXINIT length...\n");
    {int t=0;while(t<4){int n=recv(sock,buf+t,4-t,0);if(n<=0){LOG("KEX len recv err=%d\n",n);goto fail;}t+=n;}}
    uint32_t sklen=(buf[0]<<24)|(buf[1]<<16)|(buf[2]<<8)|buf[3];
    LOG("Server KEXINT len=%u\n",sklen);
    {int t=0;while(t<(int)sklen){int n=recv(sock,buf+t,sklen-t,0);if(n<=0)goto fail;t+=n;}}
    LOG("Read %u bytes of server KEXINIT\n",sklen);

    // Build KEXINIT like OpenSSH
    unsigned char pkt[2048];unsigned char *pay=pkt+4;int pp=0;
    pay[pp++]=20; // MSG_KEXINIT
    FILE*fp=fopen("/dev/urandom","rb");fread(pay+pp,1,16,fp);fclose(fp);pp+=16;

    pp=anl(pay,pp,"mlkem768x25519-sha256,sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com,"
        "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
        "diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,"
        "diffie-hellman-group14-sha256,ext-info-c,kex-strict-c-v00@openssh.com");

    pp=anl(pay,pp,"ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,"
        "ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,"
        "sk-ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,"
        "rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,"
        "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,"
        "sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256");

    pp=anl(pay,pp,"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com");
    pp=anl(pay,pp,"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com");
    pp=anl(pay,pp,"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512");
    pp=anl(pay,pp,"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512");
    pp=anl(pay,pp,"none,zlib@openssh.com");
    pp=anl(pay,pp,"none,zlib@openssh.com");
    p32(pay+pp,0);pp+=4;p32(pay+pp,0);pp+=4;
    pay[pp++]=0;p32(pay+pp,0);pp+=4;

    int rem=(pp+1)%8;int pad=(rem==0)?4:(8-rem);if(pad<4)pad=4;
    pay[pp++]=(unsigned char)pad;
    fp=fopen("/dev/urandom","rb");fread(pay+pp,1,pad,fp);fclose(fp);pp+=pad;

    int total=pp;p32(pkt,(uint32_t)total);
    LOG("Sending KEXINIT payload=%d total=%d\n",total,total+4);
    {int s=0,t=0;while(t<total+4){s=send(sock,(char*)pkt+t,total+4-t,0);if(s<=0)goto fail;t+=s;}}

    // Read response with non-blocking
    int fl=fcntl(sock,F_GETFL,0);fcntl(sock,F_SETFL,fl|O_NONBLOCK);
    unsigned char rb[65536];int tr=0;
    LOG("Waiting for response...\n");
    
    for(int i=0;i<300;i++){
        int n=recv(sock,rb+tr,sizeof(rb)-tr,0);
        if(n>0){
            tr+=n;
            LOG("+%dB (tot=%d)\n",n,tr);
            if(tr>=5){
                uint32_t plen=(rb[0]<<24)|(rb[1]<<16)|(rb[2]<<8)|rb[3];
                if((int)(plen+4)<=tr){
                    LOG("\n*** GOT PACKET len=%u msg=%u ***\n",plen,rb[5]);
                    switch(rb[5]){
                        case 7: LOG("EXT_INFO - KEX SUCCESS!\n"); break;
                        case 31: LOG("ECDH_REPLY - SUCCESS!\n"); break;
                        case 1: LOG("DISCONNECT\n"); break;
                        default: LOG("msg=%u\n",rb[5]); break;
                    }
                    hd("Data",rb,tr>64?64:tr);
                    close(sock);
                    return 0;
                }
            }
        } else if(n==0) {
            LOG("FIN received tot=%d\n",tr);
            goto fail;
        } else {
            if(errno!=EAGAIN&&errno!=EWOULDBLOCK){LOG("err=%d\n",errno);break;}
        }
        usleep(50000);
    }
    LOG("Timeout after waiting, got %d bytes\n",tr);
    if(tr>0)hd("Data",rb,tr>64?64:tr);
    close(sock);
    return 0;
fail:
    LOG("FAILED\n");
    close(sock);
    return 1;
}
