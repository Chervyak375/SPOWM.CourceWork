#pragma once

#include "Threat.h"
#include "Protocol.h"

class BadPort: public Threat
{
protected:
	unsigned short port;
	Protocol protocol;

public:
	unsigned short GetPort()
	{
		return port;
	}

	Protocol GetProtocol()
	{
		return protocol;
	}

public:
	BadPort():Threat() {}
	BadPort(unsigned short port, Protocol protocol, Risk risk): Threat(risk)
	{
		this->port = port;
		this->protocol = protocol;
	}
};