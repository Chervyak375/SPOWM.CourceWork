#pragma once

#include <Windows.h>

#include "Threat.h"
#include <string>
#include <tchar.h>
#include <iostream>
#include <Psapi.h>
#include <windows.h>
#include "Helper.h"
#include "BadFile.h"

class HiddenProcess: public BadFile
{
protected:
	DWORD PID=-1;
	
public:
	DWORD GetPID()
	{
		return PID;
	}

public:
	HiddenProcess() : BadFile(){}
	HiddenProcess(DWORD PID) : BadFile()
	{
		this->PID = PID;
		this->fullFileName = GetFullFileNameByPID(PID);
	}

private:
	std::string GetFullFileNameByPID(DWORD PID)
	{
		HANDLE processHandle = NULL;
		TCHAR filename[MAX_PATH];

		processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, PID);
		if (processHandle != NULL) {
			if (GetModuleFileNameEx(processHandle, NULL, filename, MAX_PATH) == 0) {
				return "";
			}
			else {
				return Helper::ToString(filename);
			}
			CloseHandle(processHandle);
		}
		else {
			return "";
		}
	}
};