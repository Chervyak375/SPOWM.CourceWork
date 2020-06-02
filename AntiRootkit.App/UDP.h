#pragma once

#include <Windows.h>
#include <string>

#include "IP.h"

struct UDP
{
public:
	DWORD PID;
	std::string Name;
	DWORD State;
	IP LocalIP;
	IP RemoteIP;

	UDP() {}
	UDP(DWORD pid, std::string name, DWORD state, IP localIp, IP remoteIp) : PID(pid), Name(name), State(state), LocalIP(localIp), RemoteIP(remoteIp) {}
};