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

#ifndef NESCARTSP_H
#define NESCARTSP_H

#include <string>
#include "../libncsnet/ncsnet/sys/types.h"

/* Placeholder — replaced (Task 1 Step 4) with the value the
 * implementation actually produces, pinned so field-order regressions
 * are caught by test_digest_known_vector. */
#define RTSP_KNOWN_VECTOR "50f3e879562b51028c3d089c32d7c43c"

/*
 * Build the RFC2617 Digest 'response' token (lowercase 32-char md5 hex):
 *   HA1 = md5(user:realm:pass)
 *   HA2 = md5(method:uri)
 *   response = md5(HA1:nonce:HA2)
 */
std::string rtsp_digest_response(const std::string &user,
	const std::string &realm, const std::string &pass,
	const std::string &method, const std::string &uri,
	const std::string &nonce);

/*
 * Parse the first WWW-Authenticate line of an RTSP response.
 * Returns true if a challenge is present. On a Digest challenge fills
 * realm/nonce and sets basic=false; on a Basic-only challenge sets
 * basic=true. Returns false when there is no WWW-Authenticate header.
 */
bool rtsp_parse_auth(const std::string &response, std::string &realm,
	std::string &nonce, bool &basic);

#endif
