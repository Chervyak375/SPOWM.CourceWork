#pragma once

#define _WIN32_WINNT 0x0502

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>
#include <windows.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <list>

// Windows
#define COMMAND "wmic process get ProcessId"

DWORD maxpid = 1000000;

#include "HiddenProcess.h"
#include "IScanner.h"

class ProcessorScanner : public IScanner
{
public:
	ProcessorScanner() {}

	std::list<Threat> Scan()
	{
		std::list<wint_t> result;
		std::list<wint_t> resultCache;
		std::list<Threat> hiddenPIDs;

		resultCache = checkopen();
		result.insert(result.end(), resultCache.begin(), resultCache.end());
		resultCache =checktoolhelp();
		result.insert(result.end(), resultCache.begin(), resultCache.end());

		for (wint_t r : result)
			hiddenPIDs.push_back(*(Threat*)new HiddenProcess(r));

		return hiddenPIDs;
	}

private:
	int checkps(wint_t tmppid) {

		int ok = 0;
		char pids[100];
		char compare[100];

		FILE* fich_tmp;

		fich_tmp = _popen(COMMAND, "r");


		while (!feof(fich_tmp) && ok == 0) {

			fgets(pids, 30, fich_tmp);

			int pid = atoi(pids);

			sprintf(compare, "%i\r\n", tmppid);

			if (pid == tmppid) { ok = 1; }

		}

		_pclose(fich_tmp);

		if (ok == 0) {

			return tmppid;

		}

		return -1;
	}

	std::list<wint_t> checkopen() {

		std::list<wint_t> hiddenPIDs;
		int syspids;
		DWORD home;

		HANDLE hProcess;

		HMODULE hMods[1024];
		DWORD cbNeeded;
		DWORD dwPriorityClass;

		printf("[*]Searching for Hidden processes through openprocess() scanning\n\n");

		for (syspids = 1; syspids <= maxpid; syspids = syspids + 1) {

			if ((syspids % 4) == 0) {

				hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, syspids);

				int errorn;

				errorn = GetLastError();

				//printf("Last error result : %i\n", errorn);

				if (!hProcess == NULL) {

					dwPriorityClass = 0;

					DWORD lpExitCode;

					GetExitCodeProcess(hProcess, &lpExitCode);

					if (lpExitCode != 0) {

						int result = checkps(syspids);

						if (result != -1)
							hiddenPIDs.push_back(result);

						CloseHandle(hProcess);

					}

				}
			}
		}

		return hiddenPIDs;
	}

	std::list<wint_t> checktoolhelp() {
		std::list<wint_t> hiddenPIDs;

		printf("[*]Searching for Hidden processes through Toolhelp scanning\n\n");

		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		PROCESSENTRY32 pe;

		pe.dwSize = sizeof(PROCESSENTRY32);

		BOOL retval = Process32First(hSnapshot, &pe);

		while (retval) {

			//printf("Process ID : %i\n",pe.th32ProcessID);

			int result = checkps(pe.th32ProcessID);

			if (result != -1)
				hiddenPIDs.push_back(result);

			pe.dwSize = sizeof(PROCESSENTRY32);
			retval = Process32Next(hSnapshot, &pe);
		}

		CloseHandle(hSnapshot);

		return hiddenPIDs;
	}
};