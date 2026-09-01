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

#include "include/nescahik.h"

#include <cstring>

#include "libncsnet/ncsnet/socket.h"

static const unsigned char headerIVMS[32]={
	0x00,0x00,0x00,0x20,0x63,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

static const unsigned char headerSAFARI[128]={
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x60,0x52,0x00,0x00,0x00,0x7b,0x22,0x4d,0x4f,
	0x44,0x55,0x4c,0x45,0x22,0x3a,0x22,0x43,0x45,0x52,0x54,0x49,0x46,0x49,0x43,0x41,
	0x54,0x45,0x22,0x2c,0x22,0x4f,0x50,0x45,0x52,0x41,0x54,0x49,0x4f,0x4e,0x22,0x3a,
	0x22,0x43,0x4f,0x4e,0x4e,0x45,0x43,0x54,0x22,0x2c,0x22,0x53,0x45,0x53,0x53,0x49,
	0x4f,0x4e,0x22,0x3a,0x22,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x35,0x2d,0x36,0x66,
	0x37,0x32,0x2d,0x34,0x31,0x63,0x61,0x2d,0x39,0x63,0x37,0x33,0x2d,0x62,0x34,0x37,
	0x31,0x33,0x32,0x36,0x33,0x65,0x62,0x36,0x30,0x22,0x7d,0x00
};

static bool hik_probe(int fd, const unsigned char *pkt, size_t pktlen,
	unsigned char *out, size_t outlen)
{
	if (sock_send(fd, pkt, pktlen)<=0)
		return false;
	memset(out, 0, outlen);
	return sock_recv(fd, out, outlen)>0;
}

bool hik_ivms_detect(int fd)
{
	unsigned char buf[64];
	if (!hik_probe(fd, headerIVMS, sizeof headerIVMS, buf, sizeof buf))
		return false;
	return buf[3]==0x10;
}

bool hik_safari_detect(int fd)
{
	unsigned char buf[64];
	ssize_t n;
	if (sock_send(fd, headerSAFARI, sizeof headerSAFARI)<=0)
		return false;
	memset(buf, 0, sizeof buf);
	n=sock_recv(fd, buf, sizeof buf);
	return n>0&&buf[0]!=0;
}
