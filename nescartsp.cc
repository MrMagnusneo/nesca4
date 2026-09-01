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
