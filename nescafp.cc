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

#include "include/nescafp.h"
#include "include/nescartsp.h"

#include <cstring>
#include <vector>
#include <algorithm>

#include "libncsnet/ncsnet/socket.h"

struct NESCAFP { std::vector<std::string> sigs; std::string action; };

/* 48 device fingerprints, generated from legacy nesca finder.cpp */
static const std::vector<NESCAFP> FPTABLE = {
	{ {"netwave ip camera"}, "basic|/videostream.cgi" },
	{ {"live view / - axis"}, "basic|/view/view.shtml?videos=" },
	{ {"vilar ipcamera"}, "basic|/eng/view/indexjava.html" },
	{ {"rdr.cgi"}, "basic|/rdr.cgi" },
	{ {"real-time ip camera monitoring system", "server push mode"}, "basic|/live.htm" },
	{ {"linksys.com", "tm05"}, "basic|/img/main.cgi" },
	{ {"reecam ip camera"}, "basic|/videostream.cgi" },
	{ {"/view/viewer_index.shtml"}, "basic|/mjpg/video.mjpg" },
	{ {"bridge eyeon"}, "basic|/user/index.htm" },
	{ {"ip camera control webpage", "/main/cs_motion.asp"}, "basic|/main/cs_motion.asp" },
	{ {"network camera", "/live/index2.html"}, "basic|/live/index2.html" },
	{ {"network camera", "/viewer/live/en/live.html"}, "basic|/-wvhttp-01-/open.cgi?" },
	{ {"panasonic ", ":60002/snapshotjpeg"}, "basic|/SnapshotJPEG" },
	{ {"sony network camera", "/command/inquiry.cgi?"}, "basic|/oneshotimage?" },
	{ {"network camera", "webs.cgi"}, "basic|/webs.cgi?" },
	{ {"network camera", "/viewer/live/index.html"}, "basic|/-wvhttp-01-/open.cgi?" },
	{ {"lg smart ip device"}, "basic|/digest.php" },
	{ {"nas", "/cgi-bin/data/viostor-220/viostor/viostor.cgi"}, "basic|/cgi-bin/data/viostor-220/viostor/viostor.cgi" },
	{ {"ip camera", "check_user.cgi"}, "basic|/check_user.cgi" },
	{ {"xb1"}, "IPC:IPC" },
	{ {"geovision", "ip camera", "ssi.cgi/login.htm"}, "IPC:GEO" },
	{ {"hikvision-webs", "hikvision digital", "doc/page/login.asp", "dvrdvs-webs", "app-webs", "dnvrs-webs", "lapassword", "lausername", "dologin()"}, "digest|/PSIA/Custom/SelfExt/userCheck" },
	{ {"easy cam", "easy life", "ipcamera", "/tool.js"}, "IPC:EasyCam" },
	{ {"panasonic", "/view/getuid.cgi"}, "basic|/view/getuid.cgi" },
	{ {"ipcam client", "plugins.xpi", "ipcwebcomponents", "js/upfile.js"}, "IPC:Foscam" },
	{ {"ip surveillance", "customer login"}, "basic|/cgi-bin/guest/Video.cgi?" },
	{ {"network camera", "/admin/index.shtml?"}, "basic|/admin/index.shtml?" },
	{ {"sq-webcam", "liveview.html"}, "IPC:AVIOSYS" },
	{ {"nw_camera", "/cgi-bin/getuid"}, "basic|/cgi-bin/getuid?FILE=indexnw.html" },
	{ {"micros", "/gui/gui_outer_frame.shtml"}, "basic|/gui/rem_display.shtml" },
	{ {"lapassword", "lausername", "g_ologin.dologin()"}, "basic|/ISAPI/Security/userCheck" },
	{ {"panasonic", "/config/index.cgi"}, "basic|/config/index.cgi" },
	{ {"/ui/", "sencha-touch"}, "IPC:BUFFALO" },
	{ {"digital video server", "gui.css"}, "IPC:DVS" },
	{ {"/ipcamerasetup.zip", "download player", "ipcam"}, "IPC:IPCAM" },
	{ {"dvr", "ieorforefox", "sofari"}, "IPC:IEORFOREFOX" },
	{ {"seyeon", "/app/multi/single.asp", "/app/live/sim/single.asp"}, "basic|/app/multi/single.asp" },
	{ {"maspro denkoh"}, "IPC:MASPRO" },
	{ {"webcamxp", "a valid username/password"}, "IPC:WEBCAMXP" },
	{ {"netsuveillance", "l_bgm.gif"}, "IPC:JASSUN" },
	{ {"web service", "jsmain/liveview.js"}, "IPC:BEWARD" },
	{ {"get_status.cgi", "str_device+"}, "basic|/videostream.cgi" },
	{ {"eagleeyes", "/login.cgi?rnd=", "mobile480.htm"}, "basic|/Login.cgi?rnd=000148921789481" },
	{ {"dvr_remember", "login_chk_usr_pwd"}, "IPC:JUAN" },
	{ {"qlikview"}, "basic|/QvAJAXZfc/Authenticate.aspx?_=1453661324640" },
	{ {"acti corporation"}, "IPC:ACTi" },
	{ {"airos_logo"}, "IPC:AirOS" },
	{ {"netsuveillancewebcookie", "resizel"}, "IPC:XMSECU" },
};

static std::string tolower_str(const std::string &s)
{
	std::string r=s;
	std::transform(r.begin(), r.end(), r.begin(),
		[](unsigned char c){ return std::tolower(c); });
	return r;
}

std::string httpfp_match(const std::string &body)
{
	std::string low=tolower_str(body);
	for (const auto &fp:FPTABLE) {
		bool all=true;
		for (const auto &sig:fp.sigs)
			if (low.find(sig)==std::string::npos) { all=false; break; }
		if (all&&!fp.sigs.empty())
			return fp.action;
	}
	return "";
}

bool http_digestauth(int fd, const std::string &ip, u16 port,
	const std::string &path, const std::string &login,
	const std::string &pass)
{
	u8		buf[8192];
	ssize_t		n;
	std::string	realm, nonce, host;
	bool		basic=false;

	host=ip+":"+std::to_string(port);
	/* 1) unauthenticated GET to obtain the challenge */
	std::string req="GET "+path+" HTTP/1.1\r\nHost: "+host
		+"\r\nConnection: close\r\n\r\n";
	memset(buf, 0, sizeof buf);
	n=sock_probe(fd, buf, sizeof buf-1, "%s", req.c_str());
	if (n<=0)
		return false;
	if (strstr((char*)buf, " 200"))
		return true;			/* open, no auth */
	if (!rtsp_parse_auth(std::string((char*)buf, n), realm, nonce, basic))
		return false;
	if (basic)				/* server wants Basic, not Digest */
		return false;

	/* 2) answer the Digest challenge (RFC2617, reusing nescartsp) */
	std::string resp=rtsp_digest_response(login, realm, pass,
		"GET", path, nonce);
	std::string auth="Authorization: Digest username=\""+login
		+"\", realm=\""+realm+"\", nonce=\""+nonce+"\", uri=\""+path
		+"\", response=\""+resp+"\"\r\n";
	std::string req2="GET "+path+" HTTP/1.1\r\nHost: "+host+"\r\n"
		+auth+"Connection: close\r\n\r\n";
	memset(buf, 0, sizeof buf);
	n=sock_probe(fd, buf, sizeof buf-1, "%s", req2.c_str());
	if (n<=0)
		return false;
	return strstr((char*)buf, " 200")!=NULL;
}
