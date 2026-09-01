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

#ifndef NESCAIPC_H
#define NESCAIPC_H

#define HTTP_BUFSZ 65535

#include <string>
#include <vector>
#include "../libncsnet/ncsnet/sys/types.h"

/*
 * IP-camera web bruteforce, ported from the legacy nesca IPCAuth module.
 * Each vendor ("SPEC") has a request template (GET query or POST body)
 * and a set of negative markers; a login is considered valid when the
 * HTTP response contains NONE of that vendor's negative markers.
 */

struct IPCREQUEST {
	std::string	path;		/* request-URI */
	std::string	body;		/* POST body ("" for GET) */
	std::string	ctype;		/* POST Content-Type (default urlencoded) */
	bool		post;
};

/* percent-encode per RFC3986 unreserved set (used by some vendors) */
std::string ipc_urlencode(const std::string &value);

/* true if spec is a known vendor id */
bool ipc_known_spec(const std::string &spec);

/* Build the vendor-specific request for login/pass. Returns {path,body,
 * post}; path is empty when spec is unknown. */
IPCREQUEST ipc_build_request(const std::string &spec,
	const std::string &login, const std::string &pass);

/* The vendor's negative markers (their presence means auth FAILED). */
std::vector<std::string> ipc_neg_markers(const std::string &spec);

/* Success == response non-empty and no negative marker present. */
bool ipc_check_success(const std::string &spec, const std::string &response);

/* Fingerprint a camera's landing page to a vendor SPEC (case-insensitive
 * signature match). Returns "" when no known vendor is recognised. */
std::string ipc_detect_spec(const std::string &response);

/*
 * Send one IPC auth attempt for login/pass on an already-connected fd,
 * using vendor spec. Returns true on success. Never closes fd.
 */
bool ipc_qprc_auth(int fd, const std::string &ip, u16 port,
	const std::string &login, const std::string &pass,
	const std::string &spec);

#endif
