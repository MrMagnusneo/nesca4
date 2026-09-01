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

#include "include/nescarvi.h"

#include <cstring>

#include "libncsnet/ncsnet/socket.h"

static const unsigned char RVI_START[8]=
	{0xa0,0x00,0x00,0x60,0x00,0x00,0x00,0x00};
static const unsigned char RVI_END[8]=
	{0x04,0x01,0x00,0x00,0x00,0x00,0xa1,0xaa};

std::string rvi_build_login(const std::string &login, const std::string &pass)
{
	std::string	pkt(RVI_PKT_LEN, '\0');
	size_t		ll=(login.size()>8)?8:login.size();
	size_t		pl=(pass.size()>8)?8:pass.size();

	memcpy(&pkt[0], RVI_START, 8);
	memcpy(&pkt[8], login.data(), ll);
	memcpy(&pkt[16], pass.data(), pl);
	memcpy(&pkt[24], RVI_END, 8);
	return pkt;
}

bool rvi_qprc_auth(int fd, const std::string &login, const std::string &pass)
{
	std::string	pkt;
	u8		buf[64];
	ssize_t		n;

	/* fields are 8 bytes wide; longer creds cannot be represented */
	if (login.size()>8||pass.size()>8)
		return false;

	pkt=rvi_build_login(login, pass);
	/* binary frame: must send raw (sock_probe's %s stops at first nul) */
	if (sock_send(fd, pkt.data(), pkt.size())<=0)
		return false;
	memset(buf, 0, sizeof buf);
	n=sock_recv(fd, buf, sizeof buf);
	if (n<10)
		return false;
	return buf[9]==0x08;
}
