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

#include "include/nescasmtp.h"

#include <cstring>

#include "libncsnet/ncsnet/socket.h"
#include "libncsnet/ncsnet/base64.h"

static std::string b64(const std::string &s)
{
	char	out[512];
	size_t	n=base64encode(s.data(), s.size(), out, sizeof out);
	return std::string(out, n);
}

/* send a line, read reply, return the leading 3-digit code (or -1) */
static int smtp_cmd(int fd, const std::string &line, char *buf, size_t buflen)
{
	ssize_t n;
	if (!line.empty())
		if (sock_send(fd, line.data(), line.size())<=0)
			return -1;
	memset(buf, 0, buflen);
	n=sock_recv(fd, buf, buflen-1);
	if (n<=0)
		return -1;
	return atoi(buf);
}

bool smtp_qprc_auth(int fd, const std::string &ip, u16 port,
	const std::string &login, const std::string &pass,
	long long timeout)
{
	char	buf[1024];
	int	code;

	(void)ip; (void)port; (void)timeout;

	/* greeting */
	if (smtp_cmd(fd, "", buf, sizeof buf)!=220)
		return false;
	/* EHLO */
	if (smtp_cmd(fd, "EHLO nesca\r\n", buf, sizeof buf)!=250)
		return false;
	/* AUTH LOGIN */
	if (smtp_cmd(fd, "AUTH LOGIN\r\n", buf, sizeof buf)!=334)
		return false;
	/* username */
	if (smtp_cmd(fd, b64(login)+"\r\n", buf, sizeof buf)!=334)
		return false;
	/* password */
	code=smtp_cmd(fd, b64(pass)+"\r\n", buf, sizeof buf);
	return code==235;
}
