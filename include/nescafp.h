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

#ifndef NESCAFP_H
#define NESCAFP_H

#include <string>
#include "../libncsnet/ncsnet/sys/types.h"

/*
 * Device fingerprinting + brute dispatch, ported from the legacy nesca
 * finder.cpp (sharedDetector + the _specBrute/_specWEBIPCAMBrute switch).
 * Each entry pairs a set of AND-ed content signatures with an action:
 *   "IPC:<vendor>"   -> hand off to the IPC vendor bruteforce (nescaipc)
 *   "basic|/<path>"  -> HTTP Basic-auth brute at that path
 *   "digest|/<path>" -> HTTP Digest-auth brute at that path
 */

/* Match an HTTP response body against the fingerprint table (case-
 * insensitive; every signature of an entry must be present). Returns the
 * matched action string, or "" if nothing matched. */
std::string httpfp_match(const std::string &body);

/* True if the response is an HTTP auth challenge (401 / WWW-Authenticate),
 * ported from legacy nesca Utils::isDigest — such pages get a generic
 * Basic/Digest brute at the root path. */
bool http_needs_auth(const std::string &response);

/* One HTTP Digest auth attempt for login/pass at path, on an already
 * connected fd. Reuses the RFC2617 helpers from nescartsp. Never closes
 * fd. Returns true on HTTP 200. */
bool http_digestauth(int fd, const std::string &ip, u16 port,
	const std::string &path, const std::string &login,
	const std::string &pass);

#endif
