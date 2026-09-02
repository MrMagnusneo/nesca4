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
#include "../include/nescafp.h"
#include "../libncsnet/ncsnet/sys/types.h"

static void test_match_vendor(void)
{
	assert(httpfp_match("<html>ACTi Corporation camera</html>") == "IPC:ACTi");
	assert(httpfp_match("airos_logo here") == "IPC:AirOS");
}
static void test_match_path(void)
{
	assert(httpfp_match("Netwave IP Camera") == "basic|/videostream.cgi");
	/* AND-signatures: both required */
	assert(httpfp_match("network camera /live/index2.html") == "basic|/live/index2.html");
	assert(httpfp_match("network camera") == ""); /* second sig missing */
}
static void test_match_digest(void)
{
	std::string body="hikvision-webs hikvision digital doc/page/login.asp "
		"dvrdvs-webs app-webs dnvrs-webs lapassword lausername dologin()";
	assert(httpfp_match(body) == "digest|/PSIA/Custom/SelfExt/userCheck");
}
static void test_no_match(void){ assert(httpfp_match("just a normal page")==""); }

/* fake HTTP: 401 Digest challenge, 200 for correct digest of admin/pass */
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
			char b[2048]; recv(c,b,sizeof b,0);   /* GET (no auth) */
			const char*ch="HTTP/1.1 401 Unauthorized\r\n"
				"WWW-Authenticate: Digest realm=\"cam\", nonce=\"nnn\"\r\n"
				"Content-Length: 0\r\n\r\n";
			send(c,ch,strlen(ch),0);
			int n=recv(c,b,sizeof b,0); b[n>0?n:0]=0;  /* GET with Digest */
			send(c, strstr(b,"response=")?"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
				:"HTTP/1.1 401 no\r\nContent-Length: 0\r\n\r\n", strstr(b,"response=")?38:34,0);
			close(c);
		}
	}).detach();
	return port;
}
static int fconn(u16 p){int fd=socket(AF_INET,SOCK_STREAM,0);sockaddr_in a{};a.sin_family=AF_INET;a.sin_port=htons(p);a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);connect(fd,(sockaddr*)&a,sizeof a);return fd;}

static void test_digestauth(void)
{
	u16 p=start_fake();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));
	int fd=fconn(p);
	bool ok=http_digestauth(fd,"127.0.0.1",p,"/secure","admin","pass");
	close(fd);
	assert(ok==true);
}

int main(void)
{
	test_match_vendor(); test_match_path(); test_match_digest(); test_no_match();
	test_digestauth();
	printf("test_fp: all passed\n");
	return 0;
}
