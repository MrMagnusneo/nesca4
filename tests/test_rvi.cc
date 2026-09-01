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
#include "../include/nescarvi.h"

static const unsigned char START[8]={0xa0,0x00,0x00,0x60,0x00,0x00,0x00,0x00};
static const unsigned char END[8]  ={0x04,0x01,0x00,0x00,0x00,0x00,0xa1,0xaa};

static void test_build_layout(void)
{
	std::string p = rvi_build_login("admin", "12345");
	assert(p.size() == RVI_PKT_LEN);
	assert(memcmp(p.data(), START, 8) == 0);
	assert(memcmp(p.data()+8, "admin", 5) == 0);
	assert(p[13] == 0 && p[14] == 0 && p[15] == 0);        /* nul pad */
	assert(memcmp(p.data()+16, "12345", 5) == 0);
	assert(memcmp(p.data()+24, END, 8) == 0);
}

static void test_build_truncates(void)
{
	std::string p = rvi_build_login("verylonglogin", "verylongpass");
	assert(p.size() == RVI_PKT_LEN);
	assert(memcmp(p.data()+8, "verylong", 8) == 0);        /* 8 max */
	assert(memcmp(p.data()+16, "verylong", 8) == 0);
	assert(memcmp(p.data()+24, END, 8) == 0);              /* end intact */
}

/* fake RVI server: reply with byte[9]=0x08 only for admin/12345 */
static u16 start_fake_rvi(void)
{
	int ls = socket(AF_INET, SOCK_STREAM, 0);
	int yes=1; setsockopt(ls,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes);
	sockaddr_in a{}; a.sin_family=AF_INET;
	a.sin_addr.s_addr=htonl(INADDR_LOOPBACK); a.sin_port=0;
	bind(ls,(sockaddr*)&a,sizeof a);
	socklen_t al=sizeof a; getsockname(ls,(sockaddr*)&a,&al);
	u16 port=ntohs(a.sin_port); listen(ls,4);
	std::thread([ls]{
		for (;;) {
			int c=accept(ls,nullptr,nullptr);
			if (c<0) break;
			unsigned char buf[64]={0};
			int n=recv(c,buf,sizeof buf,0);
			unsigned char rep[16]={0};
			bool ok = (n>=24 && memcmp(buf+8,"admin",5)==0
				&& memcmp(buf+16,"12345",5)==0);
			if (ok) rep[9]=0x08;
			send(c,rep,sizeof rep,0);
			close(c);
		}
	}).detach();
	return port;
}

static int fake_connect(u16 port)
{
	int fd=socket(AF_INET,SOCK_STREAM,0);
	sockaddr_in a{}; a.sin_family=AF_INET; a.sin_port=htons(port);
	a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
	connect(fd,(sockaddr*)&a,sizeof a);
	return fd;
}

static void test_auth_success(void)
{
	u16 port=start_fake_rvi();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));
	int fd=fake_connect(port);
	assert(rvi_qprc_auth(fd,"admin","12345") == true);
	close(fd);
}

static void test_auth_failure(void)
{
	u16 port=start_fake_rvi();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));
	int fd=fake_connect(port);
	assert(rvi_qprc_auth(fd,"admin","wrong") == false);
	close(fd);
}

int main(void)
{
	test_build_layout();
	test_build_truncates();
	test_auth_success();
	test_auth_failure();
	printf("test_rvi: all passed\n");
	return 0;
}
