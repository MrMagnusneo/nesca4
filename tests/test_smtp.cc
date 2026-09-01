#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <chrono>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "../include/nescasmtp.h"
#include "../libncsnet/ncsnet/base64.h"

static std::string b64(const std::string &s){char o[256];size_t n=base64encode(s.data(),s.size(),o,sizeof o);return std::string(o,n);}

/* fake SMTP: 220 greeting, 250 to EHLO, 334 twice, 235 for admin/secret else 535 */
static u16 start_fake_smtp(void)
{
	int ls=socket(AF_INET,SOCK_STREAM,0);
	int yes=1; setsockopt(ls,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes);
	sockaddr_in a{}; a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK); a.sin_port=0;
	bind(ls,(sockaddr*)&a,sizeof a);
	socklen_t al=sizeof a; getsockname(ls,(sockaddr*)&a,&al);
	u16 port=ntohs(a.sin_port); listen(ls,4);
	std::string wantu=b64("admin"), wantp=b64("secret");
	std::thread([ls,wantu,wantp]{
		for(;;){
			int c=accept(ls,nullptr,nullptr); if(c<0)break;
			char b[512];
			send(c,"220 fake ESMTP\r\n",16,0);
			recv(c,b,sizeof b,0);              /* EHLO */
			send(c,"250 ok\r\n",8,0);
			recv(c,b,sizeof b,0);              /* AUTH LOGIN */
			send(c,"334 VXNlcm5hbWU6\r\n",18,0);
			int n=recv(c,b,sizeof b,0); b[n>0?n:0]=0; std::string u(b); /* user */
			while(u.size()&&(u.back()=='\r'||u.back()=='\n'))u.pop_back();
			send(c,"334 UGFzc3dvcmQ6\r\n",18,0);
			n=recv(c,b,sizeof b,0); b[n>0?n:0]=0; std::string p(b);   /* pass */
			while(p.size()&&(p.back()=='\r'||p.back()=='\n'))p.pop_back();
			if(u==wantu&&p==wantp)send(c,"235 auth ok\r\n",13,0);
			else send(c,"535 denied\r\n",12,0);
			close(c);
		}
	}).detach();
	return port;
}
static int fconn(u16 port){int fd=socket(AF_INET,SOCK_STREAM,0);sockaddr_in a{};a.sin_family=AF_INET;a.sin_port=htons(port);a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);connect(fd,(sockaddr*)&a,sizeof a);return fd;}

static void test_ok(void){u16 p=start_fake_smtp();std::this_thread::sleep_for(std::chrono::milliseconds(40));int fd=fconn(p);assert(smtp_qprc_auth(fd,"127.0.0.1",p,"admin","secret",2000000000LL)==true);close(fd);}
static void test_bad(void){u16 p=start_fake_smtp();std::this_thread::sleep_for(std::chrono::milliseconds(40));int fd=fconn(p);assert(smtp_qprc_auth(fd,"127.0.0.1",p,"admin","wrong",2000000000LL)==false);close(fd);}

int main(void){test_ok();test_bad();printf("test_smtp: all passed\n");return 0;}
