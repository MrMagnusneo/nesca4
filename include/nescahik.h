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

#ifndef NESCAHIK_H
#define NESCAHIK_H

#include <string>
#include "../libncsnet/ncsnet/sys/types.h"

/*
 * Hikvision-family DVR/NVR support, ported from the legacy nesca
 * HikvisionLogin. Detection (checkHikk / checkSAFARI) is native. iVMS
 * credential login uses the Hikvision HCNetSDK exactly as old nesca did,
 * only loaded via dlopen at runtime instead of Windows LoadLibrary. The
 * open RVI protocol is brute-forced natively, see nescarvi.
 */

/* iVMS (Hikvision) handshake: send 32-byte probe, success if reply[3]==0x10 */
bool hik_ivms_detect(int fd);

/* SAFARI handshake: send 128-byte probe, success if reply[0]!=0 */
bool hik_safari_detect(int fd);

/*
 * iVMS credential login via the Hikvision HCNetSDK, adapted from the
 * legacy nesca hikLogin (NET_DVR_Init / NET_DVR_Login_V30). The SDK is
 * loaded at runtime with dlopen("libhcnetsdk.so"), so this always
 * compiles; when the SDK library is not present it returns false and
 * the service is effectively login-disabled (detection still works).
 * Returns true on a successful login for login/pass.
 */
bool hik_ivms_auth(const std::string &ip, u16 port,
	const std::string &login, const std::string &pass);

#endif
