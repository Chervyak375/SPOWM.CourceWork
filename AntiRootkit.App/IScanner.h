#pragma once

#include "Threat.h"

class IScanner
{
public:
	virtual std::list<Threat> Scan()=0;
};