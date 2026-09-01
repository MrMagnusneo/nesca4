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

#ifndef NESCARVI_H
#define NESCARVI_H

#include <string>
#include "../libncsnet/ncsnet/sys/types.h"

/* RVI DVR login packet is a fixed 32-byte binary frame:
 *   [0..7]   start magic (a0 00 00 60 00 00 00 00)
 *   [8..15]  login  (nul-padded, max 8 bytes)
 *   [16..23] pass   (nul-padded, max 8 bytes)
 *   [24..31] end magic (04 01 00 00 00 00 a1 aa)
 * Both login and pass must be <= 8 bytes (longer is rejected upstream).
 */
#define RVI_PKT_LEN 32

/* Build the 32-byte RVI login frame. Returns a std::string of exactly
 * RVI_PKT_LEN bytes (may contain embedded nuls). login/pass longer than
 * 8 bytes are truncated to 8. */
std::string rvi_build_login(const std::string &login, const std::string &pass);

/*
 * Send one RVI login frame on an already-connected fd and read the reply.
 * Success when reply byte [9] == 0x08. Never closes fd.
 */
bool rvi_qprc_auth(int fd, const std::string &login, const std::string &pass);

#endif
