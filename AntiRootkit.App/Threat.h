#pragma once

#include "Risk.h"

class Threat
{
protected:
	Risk risk;

public:
	Risk GetRisk()
	{
		return risk;
	}

public:
	Threat(Risk risk=Risk::Easy): risk(risk) {}
};