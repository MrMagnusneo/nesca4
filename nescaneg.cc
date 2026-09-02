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

#include "include/nescaneg.h"

#include <fstream>
#include <vector>
#include <algorithm>
#include <mutex>

static std::string g_path = DEFAULT_NEGATIVES_PATH;
static std::vector<std::string> g_neg;
static bool g_loaded = false;
static std::mutex g_mx;

static std::string lower(const std::string &s)
{
	std::string r = s;
	std::transform(r.begin(), r.end(), r.begin(),
		[](unsigned char c){ return std::tolower(c); });
	return r;
}

void negatives_setpath(const std::string &path)
{
	std::lock_guard<std::mutex> lk(g_mx);
	g_path = path;
	g_loaded = false;
	g_neg.clear();
}

static void load_once(void)
{
	std::lock_guard<std::mutex> lk(g_mx);
	if (g_loaded)
		return;
	g_loaded = true;
	std::ifstream f(g_path);
	if (!f)
		return;
	std::string line;
	while (std::getline(f, line)) {
		while (!line.empty() && (line.back()=='\r'||line.back()=='\n'
				||line.back()==' '||line.back()=='\t'))
			line.pop_back();
		if (!line.empty())
			g_neg.push_back(lower(line));
	}
}

bool is_negative(const std::string &body)
{
	load_once();
	std::string low = lower(body);
	for (const auto &n : g_neg)
		if (low.find(n) != std::string::npos)
			return true;
	return false;
}
