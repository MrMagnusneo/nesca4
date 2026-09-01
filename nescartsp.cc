/*
 * Copyright (c) 2024, oldteam. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "include/nescartsp.h"

#include <cstdlib>
#include <cstring>

#include "libncsnet/ncsnet/md5.h"
#include "libncsnet/ncsnet/socket.h"
#include "libncsnet/ncsnet/base64.h"

static std::string md5hex(const std::string &s)
{
	char *h = md5str(s.data(), s.size());
	if (!h)
		return "";
	std::string res(h);
	free(h);
	return res;
}

std::string rtsp_digest_response(const std::string &user,
	const std::string &realm, const std::string &pass,
	const std::string &method, const std::string &uri,
	const std::string &nonce)
{
	std::string ha1 = md5hex(user + ":" + realm + ":" + pass);
	std::string ha2 = md5hex(method + ":" + uri);
	return md5hex(ha1 + ":" + nonce + ":" + ha2);
}

/* extract value of key="..." searching at/after the first occurrence of key */
static bool extract_quoted(const std::string &src, const std::string &key,
	std::string &out)
{
	size_t k = src.find(key);
	if (k == std::string::npos)
		return false;
	size_t q1 = src.find('"', k);
	if (q1 == std::string::npos)
		return false;
	size_t q2 = src.find('"', q1 + 1);
	if (q2 == std::string::npos)
		return false;
	out = src.substr(q1 + 1, q2 - q1 - 1);
	return true;
}

bool rtsp_parse_auth(const std::string &response, std::string &realm,
	std::string &nonce, bool &basic)
{
	size_t w = response.find("WWW-Authenticate:");
	if (w == std::string::npos)
		return false;
	/* isolate the header line */
	size_t eol = response.find("\r\n", w);
	std::string line = response.substr(w,
		(eol == std::string::npos) ? std::string::npos : eol - w);

	if (line.find("Digest") != std::string::npos) {
		basic = false;
		extract_quoted(line, "realm=", realm);
		extract_quoted(line, "nonce=", nonce);
		return true;
	}
	if (line.find("Basic") != std::string::npos) {
		basic = true;
		extract_quoted(line, "realm=", realm);
		return true;
	}
	return false;
}

static std::string rtsp_uri(const std::string &ip, u16 port)
{
	return "rtsp://" + ip + ":" + std::to_string(port) + "/";
}

static bool rtsp_is_200(const char *resp)
{
	return strstr(resp, "RTSP/1.0 200") != NULL
		|| strstr(resp, "200 OK") != NULL;
}

bool rtsp_qprc_auth(int fd, const std::string &ip, u16 port,
	const std::string &login, const std::string &pass,
	long long timeout)
{
	u8		buf[8192];
	ssize_t		n;
	std::string	uri = rtsp_uri(ip, port);
	std::string	realm, nonce;
	bool		basic = false;

	(void)timeout; /* fd already carries its own timeout from newfd */

	/* 1) unauthenticated DESCRIBE */
	std::string req = "DESCRIBE " + uri + " RTSP/1.0\r\nCSeq: 1\r\n\r\n";
	memset(buf, 0, sizeof buf);
	n = sock_probe(fd, buf, sizeof buf - 1, "%s", req.c_str());
	if (n <= 0)
		return false;
	if (rtsp_is_200((char*)buf))
		return true; /* open, no auth */
	if (!rtsp_parse_auth(std::string((char*)buf, n), realm, nonce, basic))
		return false;

	/* 2) authenticated DESCRIBE */
	std::string authhdr;
	if (basic) {
		std::string up = login + ":" + pass;
		char enc[512];
		size_t elen = base64encode(up.data(), up.size(), enc, sizeof enc);
		authhdr = "Authorization: Basic "
			+ std::string(enc, elen) + "\r\n";
	} else {
		std::string resp = rtsp_digest_response(login, realm, pass,
			"DESCRIBE", uri, nonce);
		authhdr = "Authorization: Digest username=\"" + login
			+ "\", realm=\"" + realm + "\", nonce=\"" + nonce
			+ "\", uri=\"" + uri + "\", response=\"" + resp + "\"\r\n";
	}
	std::string req2 = "DESCRIBE " + uri + " RTSP/1.0\r\nCSeq: 2\r\n"
		+ authhdr + "\r\n";
	memset(buf, 0, sizeof buf);
	n = sock_probe(fd, buf, sizeof buf - 1, "%s", req2.c_str());
	if (n <= 0)
		return false;
	return rtsp_is_200((char*)buf);
}
