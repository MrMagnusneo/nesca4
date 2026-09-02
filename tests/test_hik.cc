#include <cassert>
#include <cstdio>
#include <cstring>
#include <thread>
#include <chrono>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "../include/nescahik.h"
#include "../libncsnet/ncsnet/sys/types.h"

/* fake server: reply is a fixed buffer; probelen distinguishes which check */
static u16 start_fake(int mark_idx, unsigned char mark_val)
{
	int ls = socket(AF_INET, SOCK_STREAM, 0);
	int yes=1; setsockopt(ls,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes);
	sockaddr_in a{}; a.sin_family=AF_INET;
	a.sin_addr.s_addr=htonl(INADDR_LOOPBACK); a.sin_port=0;
	bind(ls,(sockaddr*)&a,sizeof a);
	socklen_t al=sizeof a; getsockname(ls,(sockaddr*)&a,&al);
	u16 port=ntohs(a.sin_port); listen(ls,4);
	std::thread([ls,mark_idx,mark_val]{
		for (;;) {
			int c=accept(ls,nullptr,nullptr);
			if (c<0) break;
			unsigned char buf[256]; recv(c,buf,sizeof buf,0);
			unsigned char rep[32]={0};
			if (mark_idx>=0) rep[mark_idx]=mark_val;
			send(c,rep,sizeof rep,0);
			close(c);
		}
	}).detach();
	return port;
}
static int fconn(u16 port){int fd=socket(AF_INET,SOCK_STREAM,0);sockaddr_in a{};a.sin_family=AF_INET;a.sin_port=htons(port);a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);connect(fd,(sockaddr*)&a,sizeof a);return fd;}

static void test_ivms_hit(void){u16 p=start_fake(3,0x10);std::this_thread::sleep_for(std::chrono::milliseconds(40));int fd=fconn(p);assert(hik_ivms_detect(fd)==true);close(fd);}
static void test_ivms_miss(void){u16 p=start_fake(3,0x00);std::this_thread::sleep_for(std::chrono::milliseconds(40));int fd=fconn(p);assert(hik_ivms_detect(fd)==false);close(fd);}
static void test_safari_hit(void){u16 p=start_fake(0,0x42);std::this_thread::sleep_for(std::chrono::milliseconds(40));int fd=fconn(p);assert(hik_safari_detect(fd)==true);close(fd);}
static void test_safari_miss(void){u16 p=start_fake(-1,0);std::this_thread::sleep_for(std::chrono::milliseconds(40));int fd=fconn(p);assert(hik_safari_detect(fd)==false);close(fd);}

/* HCNetSDK is not present in the test environment: login must degrade
 * to false rather than crash. */
static void test_ivms_auth_no_sdk(void){assert(hik_ivms_auth("127.0.0.1",8000,"admin","12345")==false);}

int main(void){test_ivms_hit();test_ivms_miss();test_safari_hit();test_safari_miss();test_ivms_auth_no_sdk();printf("test_hik: all passed\n");return 0;}
