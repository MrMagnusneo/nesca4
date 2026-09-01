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

#ifndef NESCAWF_H
#define NESCAWF_H

#include <string>
#include "../libncsnet/ncsnet/sys/types.h"

/*
 * HTML login-form bruteforce, ported from the legacy nesca WebformWorker.
 * A form is described by 5 fields packed into the brute job's 'other'
 * string, tab-separated:  method \t action \t userfield \t passfield \t marker
 * Success is decided by absence of failure markers in the response
 * (the original parseResponse heuristic).
 */

struct WFFORM {
	std::string	method;		/* "GET" or "POST" */
	std::string	action;		/* form target path */
	std::string	userfield;	/* username input name */
	std::string	passfield;	/* password input name */
	std::string	marker;		/* still-on-login-page marker */
	bool		ok;
};

/* Parse the first <form> of an HTML page into a WFFORM (best-effort;
 * sensible defaults when attributes are missing). ok=false when no form
 * with a password field is found. */
WFFORM wf_parse_form(const std::string &html);

/* pack/unpack a WFFORM to/from the tab-separated 'other' string */
std::string wf_pack(const WFFORM &f);
WFFORM wf_unpack(const std::string &other);

/* true when the response indicates a successful login (non-empty and
 * none of the failure markers, incl. the form marker, are present). */
bool wf_check_success(const std::string &response, const std::string &marker);

/*
 * One webform auth attempt for login/pass on an already-connected fd,
 * using the packed form spec. Never closes fd.
 */
bool wf_qprc_auth(int fd, const std::string &ip, u16 port,
	const std::string &login, const std::string &pass,
	const std::string &packedspec);

#endif
