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
#include "../include/nescaipc.h"

static void test_urlencode(void)
{
	assert(ipc_urlencode("a b") == "a%20b");
	assert(ipc_urlencode("admin") == "admin");
	assert(ipc_urlencode("a/b") == "a%2Fb");
}

static void test_known_spec(void)
{
	assert(ipc_known_spec("Foscam"));
	assert(ipc_known_spec("GEO"));
	assert(!ipc_known_spec("NOPE"));
}

static void test_build_get(void)
{
	IPCREQUEST r = ipc_build_request("Foscam", "admin", "1234");
	assert(r.post == false);
	assert(r.path.find("admin") != std::string::npos);
	assert(r.path.find("1234") != std::string::npos);
	assert(r.path.find("CGIProxy.fcgi") != std::string::npos);
}

static void test_build_post(void)
{
	IPCREQUEST r = ipc_build_request("BUFFALO", "root", "toor");
	assert(r.post == true);
	assert(r.path == "/rpc/login");
	assert(r.body.find("user=root") != std::string::npos);
	assert(r.body.find("password=toor") != std::string::npos);
}

static void test_check_success(void)
{
	/* Foscam neg markers include <result>0</result> etc. */
	assert(ipc_check_success("Foscam", "<result>0</result>") == false);
	assert(ipc_check_success("Foscam", "<result>1</result><ok/>") == true);
	assert(ipc_check_success("Foscam", "") == false); /* empty = fail */
}

/* fake HTTP server: returns success body for admin/1234, neg marker else */
static u16 start_fake_http(void)
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
			char buf[4096]={0};
			recv(c,buf,sizeof buf-1,0);
			bool good = strstr(buf,"usr=admin") && strstr(buf,"pwd=1234");
			const char *okbody="HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n<ok/> ";
			const char *nobody="HTTP/1.1 200 OK\r\nContent-Length: 18\r\n\r\n<result>0</result>";
			const char *r = good ? okbody : nobody;
			send(c,r,strlen(r),0);
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

static void test_qprc_success(void)
{
	u16 port=start_fake_http();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));
	int fd=fake_connect(port);
	assert(ipc_qprc_auth(fd,"127.0.0.1",port,"admin","1234","Foscam")==true);
	close(fd);
}

static void test_qprc_failure(void)
{
	u16 port=start_fake_http();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));
	int fd=fake_connect(port);
	assert(ipc_qprc_auth(fd,"127.0.0.1",port,"admin","wrong","Foscam")==false);
	close(fd);
}

static void test_detect_spec(void)
{
	assert(ipc_detect_spec("<html>...CGIProxy.fcgi...") == "Foscam");
	assert(ipc_detect_spec("Server: webcamXP 5") == "WEBCAMXP");
	assert(ipc_detect_spec("<title>hi3510</title>") == "IPCAM");
	assert(ipc_detect_spec("nothing here") == "");
}

int main(void)
{
	test_urlencode();
	test_known_spec();
	test_build_get();
	test_build_post();
	test_check_success();
	test_detect_spec();
	test_qprc_success();
	test_qprc_failure();
	printf("test_ipc: all passed\n");
	return 0;
}
