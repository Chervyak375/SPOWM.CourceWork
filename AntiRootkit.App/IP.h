#pragma once

#include <Windows.h>
#include <string>

struct IP
{
public:
	std::string ip;
	DWORD Port;

public:
	IP() {}
	IP(std::string ip, DWORD port) : ip(ip), Port(port) {}

	std::string ToString()
	{
		std::string str;

		str = ip;
		str += ':';
		str += Port;

		return str;
	}
};