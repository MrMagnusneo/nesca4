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

#include "include/nescawf.h"

#include <cstring>
#include <sstream>
#include <algorithm>

#include "libncsnet/ncsnet/socket.h"

#define WF_BUFSZ 65535

static std::string lower(const std::string &s)
{
	std::string r=s;
	std::transform(r.begin(), r.end(), r.begin(),
		[](unsigned char c){ return std::tolower(c); });
	return r;
}

/* value of attr="..." (or attr='...') within tag, "" if absent */
static std::string attr(const std::string &tag, const std::string &name)
{
	std::string low=lower(tag), key=lower(name)+"=";
	size_t k=low.find(key);
	if (k==std::string::npos)
		return "";
	k+=key.size();
	if (k>=tag.size())
		return "";
	char q=tag[k];
	if (q=='"'||q=='\'') {
		size_t e=tag.find(q, k+1);
		if (e==std::string::npos)
			return "";
		return tag.substr(k+1, e-k-1);
	}
	size_t e=tag.find_first_of(" \t>", k);
	return tag.substr(k, (e==std::string::npos)?std::string::npos:e-k);
}

WFFORM wf_parse_form(const std::string &html)
{
	WFFORM		f;
	std::string	low=lower(html);
	size_t		fs, fe, p;

	f.ok=false;
	f.method="POST"; f.action="/";
	f.userfield=""; f.passfield="";

	fs=low.find("<form");
	if (fs==std::string::npos)
		return f;
	fe=low.find("</form", fs);
	std::string form=html.substr(fs,
		(fe==std::string::npos)?std::string::npos:fe-fs);
	std::string lform=lower(form);

	/* form tag attributes */
	size_t tagend=form.find('>');
	std::string ftag=form.substr(0, (tagend==std::string::npos)?
		std::string::npos:tagend);
	std::string m=attr(ftag, "method");
	if (!m.empty())
		f.method=(lower(m)=="get")?"GET":"POST";
	std::string a=attr(ftag, "action");
	if (!a.empty())
		f.action=a;

	/* walk <input ...> tags */
	for (p=0;(p=lform.find("<input", p))!=std::string::npos;) {
		size_t te=form.find('>', p);
		std::string itag=form.substr(p,
			(te==std::string::npos)?std::string::npos:te-p);
		std::string type=lower(attr(itag, "type"));
		std::string name=attr(itag, "name");
		if (type=="password"&&f.passfield.empty())
			f.passfield=name;
		else if ((type=="text"||type=="email"||type.empty())
				&&f.userfield.empty()&&!name.empty()) {
			std::string ln=lower(name);
			if (ln.find("user")!=std::string::npos
				||ln.find("name")!=std::string::npos
				||ln.find("login")!=std::string::npos
				||f.userfield.empty())
				f.userfield=name;
		}
		p=(te==std::string::npos)?lform.size():te;
	}

	if (f.passfield.empty())	/* no password field -> not a login form */
		return f;
	if (f.userfield.empty())
		f.userfield="username";
	f.marker=f.passfield;		/* password field present == still on form */
	f.ok=true;
	return f;
}

std::string wf_pack(const WFFORM &f)
{
	return f.method+"\t"+f.action+"\t"+f.userfield+"\t"
		+f.passfield+"\t"+f.marker;
}

WFFORM wf_unpack(const std::string &other)
{
	WFFORM			f;
	std::stringstream	ss(other);
	std::string		tok;
	std::string		*fields[5]={&f.method,&f.action,&f.userfield,
					&f.passfield,&f.marker};
	int			i=0;

	f.ok=false;
	for (;i<5&&std::getline(ss, tok, '\t');i++)
		*fields[i]=tok;
	f.ok=(i==5);
	return f;
}

bool wf_check_success(const std::string &response, const std::string &marker)
{
	static const char *neg[]={
		"denied", "Location:", "Authentication required", "invalid",
		"err", ".href", ".replace", ".location", "501 not implemented",
		"http-equiv", "busy", "later", "forbidden", NULL
	};
	std::string low;
	int i;

	if (response.empty())
		return false;
	low=lower(response);
	if (!marker.empty()&&low.find(lower(marker))!=std::string::npos)
		return false;
	for (i=0;neg[i];i++)
		if (low.find(lower(neg[i]))!=std::string::npos)
			return false;
	return true;
}

bool wf_qprc_auth(int fd, const std::string &ip, u16 port,
	const std::string &login, const std::string &pass,
	const std::string &packedspec)
{
	WFFORM		f=wf_unpack(packedspec);
	std::string	http, body;
	u8		buf[WF_BUFSZ];
	ssize_t		n;

	if (!f.ok)
		return false;

	if (f.method=="GET") {
		http="GET "+f.action+"?"+f.userfield+"="+login+"&"
			+f.passfield+"="+pass+" HTTP/1.1\r\nHost: "+ip
			+"\r\nConnection: close\r\n\r\n";
	} else {
		body=f.userfield+"="+login+"&"+f.passfield+"="+pass;
		http="POST "+f.action+" HTTP/1.1\r\nHost: "+ip
			+"\r\nContent-Type: application/x-www-form-urlencoded\r\n"
			"Content-Length: "+std::to_string(body.size())
			+"\r\nConnection: close\r\n\r\n"+body;
	}

	if (sock_send(fd, http.data(), http.size())<=0)
		return false;
	memset(buf, 0, sizeof buf);
	n=sock_recv(fd, buf, sizeof(buf)-1);
	if (n<=0)
		return false;
	return wf_check_success(std::string((char*)buf, n), f.marker);
}
