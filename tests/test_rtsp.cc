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
#include "../include/nescartsp.h"

/* RFC2617-style vectors. The known-vector test pins whatever md5str
 * produces so the field ordering (HA1:nonce:HA2) is locked against
 * regressions. */
static void test_digest_is_32_hex(void)
{
	std::string r = rtsp_digest_response("admin", "realm", "12345",
		"DESCRIBE", "rtsp://1.2.3.4:554/", "nonce123");
	assert(r.size() == 32);
	for (char c : r)
		assert((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
}

static void test_digest_known_vector(void)
{
	std::string r = rtsp_digest_response("a", "b", "c",
		"DESCRIBE", "rtsp://h/", "n");
	assert(r == RTSP_KNOWN_VECTOR);
}

static void test_parse_digest(void)
{
	std::string resp =
		"RTSP/1.0 401 Unauthorized\r\n"
		"CSeq: 1\r\n"
		"WWW-Authenticate: Digest realm=\"IP Camera\", nonce=\"abc123==\"\r\n"
		"\r\n";
	std::string realm, nonce; bool basic = true;
	bool ok = rtsp_parse_auth(resp, realm, nonce, basic);
	assert(ok);
	assert(basic == false);
	assert(realm == "IP Camera");
	assert(nonce == "abc123==");
}

static void test_parse_basic(void)
{
	std::string resp =
		"RTSP/1.0 401 Unauthorized\r\n"
		"WWW-Authenticate: Basic realm=\"cam\"\r\n\r\n";
	std::string realm, nonce; bool basic = false;
	bool ok = rtsp_parse_auth(resp, realm, nonce, basic);
	assert(ok);
	assert(basic == true);
}

static void test_parse_none(void)
{
	std::string resp = "RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n";
	std::string realm, nonce; bool basic = false;
	assert(rtsp_parse_auth(resp, realm, nonce, basic) == false);
}

/* Minimal fake RTSP server: first DESCRIBE -> 401 Digest challenge;
 * a DESCRIBE carrying Authorization with the correct response -> 200 OK. */
static u16 start_fake_rtsp(const std::string &user, const std::string &pass)
{
	int ls = socket(AF_INET, SOCK_STREAM, 0);
	int yes = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
	sockaddr_in a{}; a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); a.sin_port = 0;
	bind(ls, (sockaddr*)&a, sizeof a);
	socklen_t al = sizeof a; getsockname(ls, (sockaddr*)&a, &al);
	u16 port = ntohs(a.sin_port);
	listen(ls, 1);
	std::thread([ls, user, pass, port]{
		int c = accept(ls, nullptr, nullptr);
		char buf[4096];
		recv(c, buf, sizeof buf, 0);           /* first DESCRIBE */
		const char *ch =
			"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\n"
			"WWW-Authenticate: Digest realm=\"cam\", nonce=\"xyz\"\r\n\r\n";
		send(c, ch, strlen(ch), 0);
		int n = recv(c, buf, sizeof buf - 1, 0); /* authed DESCRIBE */
		buf[n > 0 ? n : 0] = 0;
		std::string uri = "rtsp://127.0.0.1:" + std::to_string(port) + "/";
		std::string want = rtsp_digest_response(user, "cam", pass,
			"DESCRIBE", uri, "xyz");
		const char *ok = "RTSP/1.0 200 OK\r\nCSeq: 2\r\n\r\n";
		const char *no = "RTSP/1.0 401 Unauthorized\r\nCSeq: 2\r\n\r\n";
		bool good = strstr(buf, want.c_str()) != nullptr;
		send(c, good ? ok : no, good ? strlen(ok) : strlen(no), 0);
		close(c); close(ls);
	}).detach();
	return port;
}

static int fake_connect(u16 port)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(port);
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	connect(fd, (sockaddr*)&a, sizeof a);
	return fd;
}

static void test_qprc_auth_success(void)
{
	u16 port = start_fake_rtsp("admin", "pass1");
	std::this_thread::sleep_for(std::chrono::milliseconds(50));
	int fd = fake_connect(port);
	bool ok = rtsp_qprc_auth(fd, "127.0.0.1", port, "admin", "pass1", 2000000000LL);
	close(fd);
	assert(ok == true);
}

static void test_qprc_auth_failure(void)
{
	u16 port = start_fake_rtsp("admin", "pass1");
	std::this_thread::sleep_for(std::chrono::milliseconds(50));
	int fd = fake_connect(port);
	bool ok = rtsp_qprc_auth(fd, "127.0.0.1", port, "admin", "wrong", 2000000000LL);
	close(fd);
	assert(ok == false);
}

int main(void)
{
	test_digest_is_32_hex();
	test_digest_known_vector();
	test_parse_digest();
	test_parse_basic();
	test_parse_none();
	test_qprc_auth_success();
	test_qprc_auth_failure();
	printf("test_rtsp: all passed\n");
	return 0;
}
