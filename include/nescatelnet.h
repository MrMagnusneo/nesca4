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

#ifndef NESCATELNET_H
#define NESCATELNET_H

#include <string>
#include "../libncsnet/ncsnet/sys/types.h"

/*
 * Telnet bruteforce (routers / IoT / DVRs). Telnet has no formal auth
 * exchange: the server negotiates options (IAC), prints a login prompt,
 * then a password prompt, then either a shell or another login prompt.
 * We answer IAC negotiation by refusing every option, then drive the
 * login/password prompts and judge success heuristically.
 */

/* Build the reply that refuses all telnet option negotiation in 'in'
 * (IAC DO x -> IAC WONT x, IAC WILL x -> IAC DONT x). Returns the reply
 * bytes (may be empty). Pure/testable. */
std::string telnet_negotiate(const u8 *in, size_t n);

/* prompt detectors (case-insensitive) */
bool telnet_is_login_prompt(const std::string &s);
bool telnet_is_pass_prompt(const std::string &s);

/* success heuristic for the post-credentials response */
bool telnet_auth_ok(const std::string &s);

/* One telnet login attempt for login/pass on an already-connected fd. */
bool telnet_qprc_auth(int fd, const std::string &ip, u16 port,
	const std::string &login, const std::string &pass,
	long long timeout);

#endif
