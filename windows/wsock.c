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

/*
 * Winsock implementation of the handful of libncsnet socket primitives
 * that nesca4's application-layer checks and bruteforce use
 * (sock_session / sock_probe / sock_recv / sock_util_timeoutns). This is
 * the TCP-connect surface only; it does NOT provide the raw-packet layer
 * (eth/arp/ip/tcp/icmp/route/intf) that SYN/ACK scanning needs -- see
 * windows/PORTING.md for the Npcap plan.
 *
 * Build only on Windows; on other platforms this file is empty.
 */
#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>

typedef uint8_t  u8;
typedef uint16_t u16;

/* one-time Winsock init */
static int wsock_ready = 0;
static void wsock_init(void)
{
	WSADATA wsa;
	if (!wsock_ready) {
		WSAStartup(MAKEWORD(2, 2), &wsa);
		wsock_ready = 1;
	}
}

int sock_util_timeoutns(int fd, long long timeoutns, int forsend, int forrecv)
{
	DWORD ms = (DWORD)(timeoutns > 0 ? timeoutns / 1000000LL : 0);
	if (ms == 0)
		ms = 1000;
	if (forrecv)
		setsockopt((SOCKET)fd, SOL_SOCKET, SO_RCVTIMEO,
			(const char*)&ms, sizeof ms);
	if (forsend)
		setsockopt((SOCKET)fd, SOL_SOCKET, SO_SNDTIMEO,
			(const char*)&ms, sizeof ms);
	return 1;
}

int sock_session(const char *dst, u16 port, long long ns, u8 *pkt, size_t pktlen)
{
	struct sockaddr_in sa;
	SOCKET s;
	int r;

	wsock_init();
	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET)
		return -1;

	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	if (inet_pton(AF_INET, dst, &sa.sin_addr) != 1)
		goto fail;

	sock_util_timeoutns((int)s, ns, 1, 1);
	if (connect(s, (struct sockaddr*)&sa, sizeof sa) == SOCKET_ERROR)
		goto fail;

	if (pkt) {
		r = recv(s, (char*)pkt, (int)pktlen - 1, 0);
		if (r == SOCKET_ERROR)
			goto fail;
		pkt[r > 0 ? r : 0] = '\0';
	}
	return (int)s;
fail:
	closesocket(s);
	return -1;
}

long sock_recv(int fd, void *pkt, size_t pktlen)
{
	int r = recv((SOCKET)fd, (char*)pkt, (int)pktlen, 0);
	return (r == SOCKET_ERROR) ? -1 : r;
}

/* mirrors libncsnet sock_probe: vsnprintf the request, send, then recv */
long sock_probe(int fd, u8 *pkt, size_t pktlen, const char *fmt, ...)
{
	va_list ap;
	char *data;
	int datalen, s, r;

	va_start(ap, fmt);
	datalen = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (datalen < 0)
		return -1;
	data = (char*)malloc(datalen + 1);
	if (!data)
		return -1;
	va_start(ap, fmt);
	vsnprintf(data, datalen + 1, fmt, ap);
	va_end(ap);

	s = send((SOCKET)fd, data, datalen, 0);
	free(data);
	if (s == SOCKET_ERROR)
		return -1;
	r = recv((SOCKET)fd, (char*)pkt, (int)pktlen - 1, 0);
	if (r == SOCKET_ERROR)
		return -1;
	pkt[r > 0 ? r : 0] = '\0';
	return r;
}

#endif /* _WIN32 */
