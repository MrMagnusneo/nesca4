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

#include "include/nescassh.h"
#include "config.h"

#ifdef HAVE_LIBSSH
#include <libssh/libssh.h>

bool ssh_brute_auth(int fd, const std::string &ip, u16 port,
	const std::string &login, const std::string &pass,
	long long timeout)
{
	ssh_session	s;
	socket_t	sock=fd;
	unsigned int	p=port;
	int		rc, zero=0;
	long		sec;
	bool		ok=false;

	sec=(timeout>0)?(long)(timeout/1000000000LL):3;
	if (sec<=0)
		sec=1;

	s=ssh_new();
	if (!s)
		return false;

	ssh_options_set(s, SSH_OPTIONS_HOST, ip.c_str());
	ssh_options_set(s, SSH_OPTIONS_PORT, &p);
	ssh_options_set(s, SSH_OPTIONS_STRICTHOSTKEYCHECK, &zero);
	ssh_options_set(s, SSH_OPTIONS_TIMEOUT, &sec);
	/* reuse the socket newfd() already opened */
	ssh_options_set(s, SSH_OPTIONS_FD, &sock);

	if (ssh_connect(s)==SSH_OK) {
		rc=ssh_userauth_password(s, login.c_str(), pass.c_str());
		ok=(rc==SSH_AUTH_SUCCESS);
	}

	ssh_disconnect(s);
	ssh_free(s);
	return ok;
}

#else /* no libssh */

bool ssh_brute_auth(int, const std::string &, u16,
	const std::string &, const std::string &, long long)
{
	return false;
}

#endif
