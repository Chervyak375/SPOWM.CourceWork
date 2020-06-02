#pragma once

#include <string>

#include "Threat.h"

class BadFile: public Threat
{
protected:
	std::string fullFileName;

public:
	std::string GetFullFileName()
	{
		return fullFileName;
	}

public:
	BadFile():Threat(){}
	BadFile(std::string fullFileName) : Threat(risk)
	{
		this->fullFileName = fullFileName;
	}
};