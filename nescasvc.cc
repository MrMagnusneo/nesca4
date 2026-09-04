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

#include "include/nescasvc.h"
#include "include/nescadata.h"   /* S_* ids */

#include <cstring>

struct NESCASVC { const char *name; int id; unsigned short defport; };

static const NESCASVC SVC[] = {
	{ "http",      S_HTTP,  80   },
	{ "ftp",       S_FTP,   21   },
	{ "rtsp",      S_RTSP,  554  },
	{ "ssh",       S_SSH,   22   },
	{ "rvi",       S_RVI,   37777},
	{ "ipc",       S_IPC,   80   },
	{ "webform",   S_WF,    80   },  /* long alias */
	{ "wf",        S_WF,    80   },
	{ "smtp",      S_SMTP,  25   },
	{ "hikvision", S_HIK,   8000 },  /* long alias */
	{ "hik",       S_HIK,   8000 },
	{ "telnet",    S_TELNET,23   },
};
static const int SVCN = (int)(sizeof(SVC)/sizeof(SVC[0]));

const char *ncs_svc_name(int id)
{
	for (int i=0;i<SVCN;i++)
		if (SVC[i].id==id)
			return SVC[i].name;   /* first (canonical/long) name */
	return "???";
}

int ncs_svc_id_prefix(const char *token, int *matchlen)
{
	int best=-1; size_t bestlen=0;
	for (int i=0;i<SVCN;i++) {
		size_t l=strlen(SVC[i].name);
		if (strncmp(token, SVC[i].name, l)==0 && l>bestlen) {
			best=SVC[i].id; bestlen=l;
		}
	}
	if (matchlen) *matchlen=(int)bestlen;
	return best;
}

unsigned short ncs_svc_defport(int id)
{
	for (int i=0;i<SVCN;i++)
		if (SVC[i].id==id)
			return SVC[i].defport;
	return 0;
}
