#pragma once

#include <Windows.h>
#include <string>

#include "IP.h"
#include "Protocol.h"

struct Connect
{
public:
	Protocol protocol;
	DWORD PID;
	std::string Name;
	DWORD State;
	IP LocalIP;
	IP RemoteIP;

	Connect() {}
	Connect(Protocol protocol, DWORD pid, std::string name, DWORD state, IP localIp, IP remoteIp): protocol(protocol), PID(pid), Name(name), State(state), LocalIP(localIp), RemoteIP(remoteIp) {}
};