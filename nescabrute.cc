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

#include "include/nescabrute.h"
#include "include/nescartsp.h"
#include "include/nescafp.h"
#include "include/nescadata.h"
#include "libncsnet/ncsnet/socket.h"
#include "libncsnet/ncsnet/utils.h"
#include <chrono>
#include <fstream>
#include <net/if.h>
#include <thread>

static std::mutex ls;	/* mutex */

inline static void _nanosleep(long nanoseconds)
{
	struct timespec ts;
	if (nanoseconds==0)
		return;
	ts.tv_sec=nanoseconds/1'000'000'000;
	ts.tv_nsec=nanoseconds%1'000'000'000;
	nanosleep(&ts, nullptr);
}

inline static u32 seed32(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts)!=0)
		return -1;
	return ((u32)(ts.tv_sec*
		1000000000ULL+ts.tv_nsec));
}

bool NESCABRUTE::init(size_t threads, const std::string &ip, u16 port,
	u8 service, long long timeout, std::vector<std::string> login,
	std::vector<std::string> pass)
{
	size_t j;

	/* primum connect */
	this->restimeout=(timeout==-1)
		?START_TIMEOUT:timeout;
	for (j=0;j<3;j++) {
		newfd(ip, port, service, this->restimeout);
		if (!this->fds.empty())
			break;
	}
	if (this->fds.empty())
		return 0;
	this->restimeout=(timeout==-1)
		?(rtt*3):timeout;

	/* cetera coonections */
	for (j=1,threads--;j<=threads;j++)
		newfd(ip, port, service, this->restimeout);

	return 1;
}

void NESCABRUTE::newfd(const std::string &ip, u16 port,
	u8 service, long long timeout)
{
	std::chrono::high_resolution_clock::time_point	start, end;
	std::chrono::nanoseconds			duration;
	int						res=0, code=0;
	u8						temp[BUFSIZ];

	if (!ok)
		start=std::chrono::high_resolution_clock::now();

	res=((service==FTP_BRUTEFORCE)?(sock_session(ip.c_str(), port,
		 timeout, temp, BUFSIZ))
		:(sock_session(ip.c_str(), port, timeout, NULL, 0)));

	if (!ok)
		end=std::chrono::high_resolution_clock::now();
	if (!ok) {
		duration=std::chrono::duration_cast
			<std::chrono::nanoseconds>(end-start);
		rtt=duration.count();
		ok=1;
	}
	if (service==FTP_BRUTEFORCE) {
		code=atoi((char*)temp);
		if (code!=R_220)
			return;
	}

	ls.lock();
	this->fds.push_back(res);
	ls.unlock();
}

void NESCABRUTE::probe(int fd, u8 service, const std::string &ip,
	const std::string &path, const std::string &login,
	const std::string &pass, std::atomic<bool> *auth)
{
	if (*auth)
		return;
	switch (service) {
		case FTP_BRUTEFORCE:
			*auth=ftp_qprc_auth(fd, login.c_str(), pass.c_str());
			return;
		case HTTP_BRUTEFORCE:
			/* 'path' may carry a device-specific brute target as
			 * "digest|/p" or "basic|/p" (from the fingerprinter);
			 * a bare path stays plain Basic auth. */
			if (path.rfind("digest|", 0)==0)
				*auth=http_digestauth(fd, ip, srvport,
					path.substr(7), login, pass);
			else {
				std::string bp=(path.rfind("basic|", 0)==0)?
					path.substr(6):path;
				*auth=http_basicauth(fd, ip.c_str(), bp.c_str(),
					login.c_str(), pass.c_str());
			}
			return;
		case RTSP_BRUTEFORCE:
			*auth=rtsp_qprc_auth(fd, ip, srvport, login, pass,
				restimeout);
			return;
		case SSH_BRUTEFORCE:
			*auth=ssh_brute_auth(fd, ip, srvport, login, pass,
				restimeout);
			return;
		case RVI_BRUTEFORCE:
			*auth=rvi_qprc_auth(fd, login, pass);
			return;
		case IPC_BRUTEFORCE:
			/* 'path' carries the vendor SPEC for IPC jobs */
			*auth=ipc_qprc_auth(fd, ip, srvport, login, pass, path);
			return;
		case WF_BRUTEFORCE:
			/* 'path' carries the packed form spec for WF jobs */
			*auth=wf_qprc_auth(fd, ip, srvport, login, pass, path);
			return;
		case SMTP_BRUTEFORCE:
			*auth=smtp_qprc_auth(fd, ip, srvport, login, pass,
				restimeout);
			return;
		case HIK_BRUTEFORCE:
			/* 'path'=="ivms" -> HCNetSDK login (SDK loaded at runtime) */
			if (path=="ivms")
				*auth=hik_ivms_auth(ip, srvport, login, pass);
			return;
	}
}

NESCABRUTE::NESCABRUTE(size_t threads, const std::string &ip, const std::string &path,
	u16 port, long long timeout, u8 service, long long delay, std::vector<std::string> login,
	std::vector<std::string> pass)
{
	std::vector<std::future<void>>	futures;
	std::atomic<bool>		auth(false);
	size_t				i=0, realthreads=0;

	this->srvport=port;

	realthreads=((threads>(login.size()*pass.size())))?
		(login.size()*pass.size()/* /2 */):threads;

	if (!(init(realthreads, ip, port, service, timeout, login, pass)))
		return;

	NESCAPOOL pool(realthreads);
	for (const auto &l:login) {
		for (const auto &p:pass) {
			if ((i+1)>fds.size())
				i=0;
			futures.push_back(pool.enqueue(&NESCABRUTE::probe, this, fds[i],
				 service, ip, path, l, p, &auth));
			for (;!auth&&futures.back().wait_for(std::chrono::milliseconds(10))
					!=std::future_status::ready;)
				std::this_thread::yield();
			if (auth) {
				respass=p;
				reslogin=l;
				goto exit;
			}
			i++;
			_nanosleep(delay);
		}
	}

exit:
	for (auto&future:futures)
		future.get();
}

NESCABRUTE::~NESCABRUTE(void)
{
	for (const auto&fd:fds)
		if (fd!=-1)
			close(fd);
}

std::string NESCABRUTE::LOGIN(void)
{
	if (!reslogin.empty())
		return reslogin;
	return "";
}

std::string NESCABRUTE::PASS(void)
{
	if (!reslogin.empty())
		return respass;
	return "";
}

std::string NESCABRUTE::GETRESULTINNESCASTYLE(void)
{
	if (!LOGIN().empty()&&!PASS().empty())
		return (LOGIN()+":"+PASS()+"@");
	return "";
}

static std::vector<std::string>
	l={"root", "admin", "12345"},
	p={"root", "12345", "1111", "admin", "1234"};

static void INIT_NESCABRUTEFORCE(NESCADATA *ncsdata)
{
	std::string lpath,ppath, tmp;
	lpath="resources/login.txt";
	ppath="resources/pass.txt";
	if (ncsdata->opts.check_login_flag())
		lpath=ncsdata->opts.get_login_param();
	if (ncsdata->opts.check_pass_flag())
		ppath=ncsdata->opts.get_pass_param();
	std::ifstream f(lpath);
	std::ifstream f1(ppath);
	if (!f||!f1)
		return;
	l.clear(),p.clear();
	for (;std::getline(f, tmp);)
		l.push_back(tmp);
	for (;std::getline(f1, tmp);)
		p.push_back(tmp);
	f.close();
	f1.close();
}

void NESCABRUTEFORCE(NESCADATA *ncsdata)
{
	long long timeout, delay;
	size_t i, pos, threads;

	INIT_NESCABRUTEFORCE(ncsdata);

	timeout=(ncsdata->opts.check_wait_brute_flag())?
		delayconv(ncsdata->opts.get_wait_brute_param().c_str()):-1;
	delay=(ncsdata->opts.check_delay_brute_flag())?
		delayconv(ncsdata->opts.get_delay_brute_param().c_str()):0;
	threads=(ncsdata->opts.check_threads_brute_flag())?
		std::stoi(ncsdata->opts.get_threads_brute_param()):5;

	for (const auto&t:ncsdata->targets) {
		if (t->get_num_bruteforce()<=0)
			continue;
		for (i=0;i<t->get_num_bruteforce();i++) {
			NESCABRUTEI tmp=t->get_bruteforce(i);

			NESCABRUTE brute(threads, t->get_mainip(), tmp.other,
				tmp.port, timeout, tmp.service, delay, l, p);

			if (!brute.LOGIN().empty()&&!brute.PASS().empty()){
				for (pos=0;pos<t->get_num_port();pos++)
					if (t->get_port(pos).port==tmp.port)
						break;
				t->add_info_service(t->get_real_port(pos), tmp.service,
					brute.GETRESULTINNESCASTYLE(), "passwd");
			}
		}
	}
}
