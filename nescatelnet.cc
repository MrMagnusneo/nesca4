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

#include "include/nescatelnet.h"
#include "include/nescautil.h"

#include <cstring>

#include "libncsnet/ncsnet/socket.h"

/* telnet control bytes */
#define IAC  255
#define WILL 251
#define WONT 252
#define DO   253
#define DONT 254

std::string telnet_negotiate(const u8 *in, size_t n)
{
	std::string out;
	for (size_t i=0;i+2<n;i++) {
		if (in[i]!=IAC)
			continue;
		u8 cmd=in[i+1], opt=in[i+2];
		if (cmd==DO)        { out+=(char)IAC; out+=(char)WONT; out+=(char)opt; }
		else if (cmd==WILL) { out+=(char)IAC; out+=(char)DONT; out+=(char)opt; }
		i+=2;
	}
	return out;
}

bool telnet_is_login_prompt(const std::string &s)
{
	std::string l=ncs_tolower(s);
	return l.find("login:")!=std::string::npos
		|| l.find("username:")!=std::string::npos
		|| l.find("user:")!=std::string::npos;
}

bool telnet_is_pass_prompt(const std::string &s)
{
	return ncs_tolower(s).find("password")!=std::string::npos;
}

bool telnet_auth_ok(const std::string &s)
{
	if (s.empty())
		return false;
	std::string l=ncs_tolower(s);
	if (l.find("incorrect")!=std::string::npos
		|| l.find("fail")!=std::string::npos
		|| l.find("denied")!=std::string::npos
		|| l.find("invalid")!=std::string::npos
		|| l.find("bad ")!=std::string::npos)
		return false;
	if (telnet_is_login_prompt(l)||telnet_is_pass_prompt(l))
		return false;
	if (l.find('#')!=std::string::npos||l.find('$')!=std::string::npos
		||l.find('>')!=std::string::npos||l.find("welcome")!=std::string::npos
		||l.find("last login")!=std::string::npos)
		return true;
	return false;
}

/* read one chunk, auto-answering IAC negotiation, return the visible text */
static std::string telnet_read(int fd)
{
	u8 buf[4096];
	ssize_t n=sock_recv(fd, buf, sizeof buf);
	if (n<=0)
		return "";
	std::string reply=telnet_negotiate(buf, (size_t)n);
	if (!reply.empty())
		sock_send(fd, reply.data(), reply.size());
	std::string out;
	for (ssize_t i=0;i<n;i++) {
		if (buf[i]==IAC) { i+=2; continue; }
		out+=(char)buf[i];
	}
	return out;
}

bool telnet_qprc_auth(int fd, const std::string &ip, u16 port,
	const std::string &login, const std::string &pass,
	long long timeout)
{
	(void)ip; (void)port; (void)timeout;
	std::string acc;
	int i;

	for (i=0;i<4;i++) {
		acc+=telnet_read(fd);
		if (telnet_is_login_prompt(acc))
			break;
	}
	std::string l=login+"\r\n";
	if (sock_send(fd, l.data(), l.size())<=0)
		return false;

	acc.clear();
	for (i=0;i<4;i++) {
		acc+=telnet_read(fd);
		if (telnet_is_pass_prompt(acc))
			break;
	}
	std::string p=pass+"\r\n";
	if (sock_send(fd, p.data(), p.size())<=0)
		return false;

	acc.clear();
	for (i=0;i<4;i++) {
		std::string r=telnet_read(fd);
		if (r.empty())
			break;
		acc+=r;
		if (telnet_auth_ok(acc)||telnet_is_login_prompt(acc))
			break;
	}
	return telnet_auth_ok(acc);
}
