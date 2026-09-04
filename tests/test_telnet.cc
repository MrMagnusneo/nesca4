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
#include "../include/nescatelnet.h"

static void test_negotiate(void)
{
	/* IAC DO 24 (0xFF 0xFD 0x18) -> IAC WONT 24 (0xFF 0xFC 0x18) */
	unsigned char in[]={255,253,24, 255,251,3};
	std::string r=telnet_negotiate(in, sizeof in);
	unsigned char exp[]={255,252,24, 255,254,3};
	assert(r.size()==6 && memcmp(r.data(),exp,6)==0);
	assert(telnet_negotiate((const unsigned char*)"hello",5).empty());
}
static void test_prompts(void)
{
	assert(telnet_is_login_prompt("router login: "));
	assert(telnet_is_login_prompt("Username: "));
	assert(!telnet_is_login_prompt("welcome"));
	assert(telnet_is_pass_prompt("Password: "));
	assert(!telnet_is_pass_prompt("login:"));
}
static void test_authok(void)
{
	assert(telnet_auth_ok("BusyBox v1.0\r\n# ")==true);
	assert(telnet_auth_ok("Login incorrect\r\nlogin: ")==false);
	assert(telnet_auth_ok("login: ")==false);
	assert(telnet_auth_ok("")==false);
}

/* fake telnet server: IAC negotiation, login:, password:, then shell for
 * admin/admin, else 'Login incorrect' + re-prompt */
static std::string strip_iac(const std::string &in){std::string o;for(size_t i=0;i<in.size();i++){if((unsigned char)in[i]==255){i+=2;continue;}o+=in[i];}return o;}
/* read one CRLF-terminated line, stripping telnet IAC (like a real server) */
static std::string recvline(int c){std::string acc;char b[256];for(;;){int n=recv(c,b,sizeof b,0);if(n<=0)break;acc.append(b,n);acc=strip_iac(acc);size_t nl=acc.find('\n');if(nl!=std::string::npos){std::string line=acc.substr(0,nl);while(line.size()&&(line.back()=='\r'||line.back()=='\n'))line.pop_back();return line;}}return strip_iac(acc);}
static u16 start_fake(void)
{
	int ls=socket(AF_INET,SOCK_STREAM,0);
	int yes=1; setsockopt(ls,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes);
	sockaddr_in a{}; a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_LOOPBACK); a.sin_port=0;
	bind(ls,(sockaddr*)&a,sizeof a);
	socklen_t al=sizeof a; getsockname(ls,(sockaddr*)&a,&al);
	u16 port=ntohs(a.sin_port); listen(ls,4);
	std::thread([ls]{
		for(;;){int c=accept(ls,nullptr,nullptr); if(c<0)break;
			unsigned char neg[]={255,253,24};        /* IAC DO 24 */
			send(c,neg,sizeof neg,0);
			send(c,"\r\nrouter login: ",16,0);
			std::string u=recvline(c);
			send(c,"Password: ",10,0);
			std::string p=recvline(c);
			if(u=="admin"&&p=="admin") send(c,"\r\nBusyBox v1.22\r\n# ",19,0);
			else send(c,"\r\nLogin incorrect\r\nrouter login: ",33,0);
			close(c);
		}
	}).detach();
	return port;
}
static int fconn(u16 p){int fd=socket(AF_INET,SOCK_STREAM,0);sockaddr_in a{};a.sin_family=AF_INET;a.sin_port=htons(p);a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);connect(fd,(sockaddr*)&a,sizeof a);return fd;}

static void test_ok(void){u16 p=start_fake();std::this_thread::sleep_for(std::chrono::milliseconds(40));int fd=fconn(p);assert(telnet_qprc_auth(fd,"127.0.0.1",p,"admin","admin",2000000000LL)==true);close(fd);}
static void test_bad(void){u16 p=start_fake();std::this_thread::sleep_for(std::chrono::milliseconds(40));int fd=fconn(p);assert(telnet_qprc_auth(fd,"127.0.0.1",p,"admin","wrong",2000000000LL)==false);close(fd);}

int main(void)
{
	test_negotiate(); test_prompts(); test_authok();
	test_ok(); test_bad();
	printf("test_telnet: all passed\n");
	return 0;
}
