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

#include "include/nescaipc.h"

#include <cstdio>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <map>

#include "libncsnet/ncsnet/socket.h"

std::string ipc_urlencode(const std::string &value)
{
	std::ostringstream	o;
	o.fill('0');
	o<<std::hex;
	for (unsigned char c:value) {
		if (isalnum(c)||c=='-'||c=='_'||c=='.'||c=='~') {
			o<<c;
			continue;
		}
		o<<std::uppercase<<'%'<<std::setw(2)<<int(c)<<std::nouppercase;
	}
	return o.str();
}

/* negative markers per vendor (presence == auth failed) */
static const std::map<std::string, std::vector<std::string>> IPC_NEG = {
	{"IPC",		{"<UserGroup>Invalid</UserGroup>"}},
	{"GEO",		{"Access denied", "ErrNoSuchUsr.htm"}},
	{"EasyCam",	{"Set-Cookie: usrLevel=-1;path=/"}},
	{"Foscam",	{"<result>0</result>", "<result>-1</result>",
			 "<result>-2</result>", "<result>-3</result>",
			 "<result>-4</result>", "<result>-5</result>",
			 "<result>-6</result>", "<result>-7</result>"}},
	{"AVIOSYS",	{"Password Error"}},
	{"BUFFALO",	{"403 Forbidden"}},
	{"DVS",		{"Non-Existed"}},
	{"IPCAM",	{"var check=\"0\"", "var authLevel =\"0\";"}},
	{"IEORFOREFOX",	{"AAA()", "is incorrect", "HTTP/1.0 302 Found"}},
	{"MASPRO",	{"action=\"setup_login.cgi\""}},
	{"WEBCAMXP",	{"Not logged in"}},
	{"JASSUN",	{"Log in failed"}},
	{"BEWARD",	{"/error.asp"}},
	{"JUAN",	{"errno=\"4\""}},
	{"ACTi",	{"ERROR: "}},
	{"AirOS",	{"Invalid credentials"}},
	{"XMSECU",	{"Log in failed", "errornumber=-1"}},
};

bool ipc_known_spec(const std::string &spec)
{
	return IPC_NEG.find(spec)!=IPC_NEG.end();
}

std::vector<std::string> ipc_neg_markers(const std::string &spec)
{
	auto it=IPC_NEG.find(spec);
	if (it==IPC_NEG.end())
		return {};
	return it->second;
}

static std::string fmt(const char *f, const std::string &a,
	const std::string &b, const std::string &c, const std::string &d)
{
	char	buf[1024];
	snprintf(buf, sizeof buf, f, a.c_str(), b.c_str(), c.c_str(), d.c_str());
	return std::string(buf);
}

IPCREQUEST ipc_build_request(const std::string &spec,
	const std::string &login, const std::string &pass)
{
	IPCREQUEST	r;
	const std::string &L=login, &P=pass;

	r.post=false;
	r.ctype="application/x-www-form-urlencoded";

	if (spec=="IPC"||spec=="EasyCam")
		r.path=fmt("/login.xml?user=%s&usr=%s&password=%s&pwd=%s", L, L, P, P);
	else if (spec=="GEO")
		r.path=fmt("/Login.cgi?username=%s&password=%s", L, P, "", "");
	else if (spec=="Foscam")
		r.path=fmt("/cgi-bin/CGIProxy.fcgi?usr=%s&pwd=%s&cmd=logIn&usrName=%s&pwd=%s", L, P, L, P);
	else if (spec=="AVIOSYS")
		r.path=fmt("/check_user.html?UserName=%s&PassWord=%s", L, P, "", "");
	else if (spec=="IPCAM")
		r.path=fmt("/cgi-bin/hi3510/checkuser.cgi?&-name=%s&-passwd=%s&-time=1416767330831", L, P, "", "");
	else if (spec=="BEWARD")
		r.path=fmt("/webs/httplogin?username=%s&password=%s&UserID=45637757", L, P, "", "");
	else if (spec=="JUAN") {
		std::string eL=ipc_urlencode(L), eP=ipc_urlencode(P);
		r.path="/cgi-bin/gw.cgi?xml=%3Cjuan%20ver=%22%22%20squ=%22%22%20dir=%22%22%3E%3Cenvload%20type=%220%22%20usr=%22"
			+eL+"%22%20pwd=%22"+eP+"%22/%3E%3C/juan%3E&_=1450923182693";
	}
	else if (spec=="IEORFOREFOX") {
		r.post=true; r.path="/logincheck.rsp?type=1";
		r.body=fmt("username=%s&userpwd=%s", L, P, "", "");
	}
	else if (spec=="BUFFALO") {
		r.post=true; r.path="/rpc/login";
		r.body=fmt("user=%s&password=%s", L, P, "", "");
	}
	else if (spec=="DVS") {
		r.post=true; r.path="/login";
		r.body=fmt("langs=en&user=%s&password=%s&submit=+Login+", L, P, "", "");
	}
	else if (spec=="MASPRO") {
		r.post=true; r.path="/setup_login.cgi";
		r.body=fmt("check_username=%s&check_password=%s&login=", L, P, "", "");
	}
	else if (spec=="WEBCAMXP") {
		r.post=true; r.path="/login.html";
		r.body=fmt("username=%s&password=%s&Redir=/", L, P, "", "");
	}
	else if (spec=="JASSUN"||spec=="XMSECU") {
		r.post=true; r.path="/Login.htm";
		r.body=fmt("command=login&username=%s&password=%s", L, P, "", "");
	}
	else if (spec=="ACTi") {
		r.post=true; r.path="/cgi-bin/videoconfiguration.cgi";
		r.body=fmt("LOGIN_ACCOUNT=%s&LOGIN_PASSWORD=%s", L, P, "", "");
	}
	else if (spec=="AirOS") {
		r.post=true; r.path="/login.cgi";
		const std::string bnd="---------------------------170381307613422";
		r.ctype="multipart/form-data; boundary="+bnd;
		r.body="--"+bnd+"\r\nContent-Disposition: form-data; name=\"uri\"\r\n\r\n/\r\n"
			"--"+bnd+"\r\nContent-Disposition: form-data; name=\"username\"\r\n\r\n"+L+"\r\n"
			"--"+bnd+"\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n"+P+"\r\n"
			"--"+bnd+"--\r\n";
	}
	/* unknown spec -> empty path */
	return r;
}

/* distinctive login-page signatures, checked case-insensitively */
static const std::vector<std::pair<std::string, std::string>> IPC_SIG = {
	{"CGIProxy.fcgi", "Foscam"},	{"foscam",	"Foscam"},
	{"hi3510",	"IPCAM"},	{"webcamxp",	"WEBCAMXP"},
	{"airos",	"AirOS"},	{"ubnt",	"AirOS"},
	{"beward",	"BEWARD"},	{"geohttpserver","GEO"},
	{"geovision",	"GEO"},		{"acti",	"ACTi"},
	{"jassun",	"JASSUN"},	{"aviosys",	"AVIOSYS"},
};

static std::string tolower_str(const std::string &s)
{
	std::string r=s;
	for (auto &c:r)
		c=(char)tolower((unsigned char)c);
	return r;
}

std::string ipc_detect_spec(const std::string &response)
{
	std::string low=tolower_str(response);
	for (const auto &sig:IPC_SIG)
		if (low.find(tolower_str(sig.first))!=std::string::npos)
			return sig.second;
	return "";
}

bool ipc_check_success(const std::string &spec, const std::string &response)
{
	if (response.empty())
		return false;
	for (const auto &m:ipc_neg_markers(spec))
		if (response.find(m)!=std::string::npos)
			return false;
	return true;
}

bool ipc_qprc_auth(int fd, const std::string &ip, u16 port,
	const std::string &login, const std::string &pass,
	const std::string &spec)
{
	IPCREQUEST	req;
	std::string	http;
	u8		buf[HTTP_BUFSZ];
	ssize_t		n;

	if (!ipc_known_spec(spec))
		return false;
	req=ipc_build_request(spec, login, pass);
	if (req.path.empty())
		return false;

	if (req.post) {
		http="POST "+req.path+" HTTP/1.1\r\nHost: "+ip+":"
			+std::to_string(port)+"\r\nContent-Type: "+req.ctype
			+"\r\nContent-Length: "+std::to_string(req.body.size())
			+"\r\nConnection: close\r\n\r\n"+req.body;
	} else {
		http="GET "+req.path+" HTTP/1.1\r\nHost: "+ip+":"
			+std::to_string(port)+"\r\nConnection: close\r\n\r\n";
	}

	if (sock_send(fd, http.data(), http.size())<=0)
		return false;
	memset(buf, 0, sizeof buf);
	n=sock_recv(fd, buf, sizeof(buf)-1);
	if (n<=0)
		return false;
	return ipc_check_success(spec, std::string((char*)buf, n));
}
