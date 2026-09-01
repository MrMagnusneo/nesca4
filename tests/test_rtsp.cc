#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
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

int main(void)
{
	test_digest_is_32_hex();
	test_digest_known_vector();
	test_parse_digest();
	test_parse_basic();
	test_parse_none();
	printf("test_rtsp: all passed\n");
	return 0;
}
