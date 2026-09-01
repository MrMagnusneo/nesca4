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
#include "../include/nescawf.h"

static void test_parse_form(void)
{
	std::string html =
		"<html><body>"
		"<form action=\"/login.php\" method=\"post\">"
		"<input type=\"text\" name=\"user\">"
		"<input type=\"password\" name=\"pass\">"
		"</form></body></html>";
	WFFORM f = wf_parse_form(html);
	assert(f.ok);
	assert(f.method == "POST");
	assert(f.action == "/login.php");
	assert(f.userfield == "user");
	assert(f.passfield == "pass");
}

static void test_parse_form_defaults(void)
{
	/* no method attr -> POST; no explicit user field -> default */
	std::string html =
		"<form action=\"/auth\">"
		"<input name=\"password\" type=\"password\"></form>";
	WFFORM f = wf_parse_form(html);
	assert(f.ok);
	assert(f.method == "POST");
	assert(f.action == "/auth");
	assert(f.passfield == "password");
}

static void test_no_form(void)
{
	WFFORM f = wf_parse_form("<html>no forms here</html>");
	assert(!f.ok);
}

static void test_pack_unpack(void)
{
	WFFORM f; f.method="POST"; f.action="/a"; f.userfield="u";
	f.passfield="p"; f.marker="m"; f.ok=true;
	WFFORM g = wf_unpack(wf_pack(f));
	assert(g.method=="POST" && g.action=="/a" && g.userfield=="u"
		&& g.passfield=="p" && g.marker=="m");
}

static void test_check_success(void)
{
	assert(wf_check_success("Welcome to the dashboard", "loginform") == true);
	assert(wf_check_success("Access denied", "loginform") == false);
	assert(wf_check_success("still <form id=loginform>", "loginform") == false);
	assert(wf_check_success("", "x") == false);
}

/* fake HTTP: dashboard for admin/secret, "invalid" otherwise */
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
			bool good = strstr(buf,"user=admin") && strstr(buf,"pass=secret");
			const char *ok="HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\ndashboard";
			const char *no="HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ninvalid";
			const char *r=good?ok:no;
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
	WFFORM f; f.method="POST"; f.action="/login"; f.userfield="user";
	f.passfield="pass"; f.marker="loginform"; f.ok=true;
	assert(wf_qprc_auth(fd,"127.0.0.1",port,"admin","secret",wf_pack(f))==true);
	close(fd);
}

static void test_qprc_failure(void)
{
	u16 port=start_fake_http();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));
	int fd=fake_connect(port);
	WFFORM f; f.method="POST"; f.action="/login"; f.userfield="user";
	f.passfield="pass"; f.marker="loginform"; f.ok=true;
	assert(wf_qprc_auth(fd,"127.0.0.1",port,"admin","wrong",wf_pack(f))==false);
	close(fd);
}

int main(void)
{
	test_parse_form();
	test_parse_form_defaults();
	test_no_form();
	test_pack_unpack();
	test_check_success();
	test_qprc_success();
	test_qprc_failure();
	printf("test_wf: all passed\n");
	return 0;
}
