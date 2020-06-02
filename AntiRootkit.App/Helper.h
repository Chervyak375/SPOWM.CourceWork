#pragma once
#include <string>
#include <stdio.h>
#include <cassert>
#include <iomanip>
#include <iostream>
#include <vector>
#include <Windows.h>
#include <sstream>
#include <windows.h>
#include <winsock.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <locale>
#include <codecvt>

#include "Connect.h"

#pragma comment(lib,"psapi")
#pragma comment(lib,"iphlpapi")
#pragma comment(lib,"wsock32")

using namespace std;


static class Helper
{
public:
    static std::string GetDate()
    {
        std::time_t t = std::time(0);
        std::tm* now = std::localtime(&t);
        std::stringstream data;
        data << (now->tm_year + 1900) << '-'
            << (now->tm_mon + 1) << '-'
            << now->tm_mday
            << "\n";

        return data.str();
    }

    static std::string ConvertRiskToString(Risk risk)
    {
        switch (risk)
        {
        case Easy:
            return "Easy";
        case Normal:
            return "Normal";
        case Attention:
            return "Attention";
        default:
            "N/A";
        }
    }

    static std::string ConvertProtocolToString(Protocol protocol)
    {
        switch (protocol)
        {
        case Protocol::TCP:
            return "TCP";
        case Protocol::UDP:
            return "UDP";
        case Protocol::TCP_UDP:
            return "TCP/UDP";
        default:
            return "N/A";
        }
    }

	static std::string GetOSVersion()
	{
        const auto system = L"kernel32.dll";
        std::stringstream versionS;
        DWORD dummy;
        const auto cbInfo =
            GetFileVersionInfoSizeExW(FILE_VER_GET_NEUTRAL, system, &dummy);
        std::vector<char> buffer(cbInfo);
        GetFileVersionInfoExW(FILE_VER_GET_NEUTRAL, system, dummy,
            buffer.size(), &buffer[0]);
        void* p = nullptr;
        UINT size = 0;
        ::VerQueryValueW(buffer.data(), L"\\", &p, &size);
        assert(size >= sizeof(VS_FIXEDFILEINFO));
        assert(p != nullptr);
        auto pFixed = static_cast<const VS_FIXEDFILEINFO*>(p);
        versionS << HIWORD(pFixed->dwFileVersionMS) << '.'
            << LOWORD(pFixed->dwFileVersionMS) << '.'
            << HIWORD(pFixed->dwFileVersionLS) << '.'
            << LOWORD(pFixed->dwFileVersionLS);

        return versionS.str();
	}

    static std::list<Connect> GetTCP()
    {
        std::list<Connect> tcps;
        vector<unsigned char> buffer;
        DWORD dwSize = sizeof(MIB_TCPTABLE_OWNER_PID);
        DWORD dwRetValue = 0;

        do {
            buffer.resize(dwSize, 0);
            dwRetValue = GetExtendedTcpTable(buffer.data(), &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        } while (dwRetValue == ERROR_INSUFFICIENT_BUFFER);
        if (dwRetValue == ERROR_SUCCESS)
        {
            PMIB_TCPTABLE_OWNER_PID ptTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
            for (DWORD i = 0; i < ptTable->dwNumEntries; i++)
            {
                Connect connect;

                connect.protocol = Protocol::TCP;
                connect.PID = ptTable->table[i].dwOwningPid;
                connect.Name = processName(ptTable->table[i].dwOwningPid);
                connect.State = ptTable->table[i].dwState;
                connect.LocalIP = *new IP(dwordToString(ptTable->table[i].dwLocalAddr), htons((unsigned short)ptTable->table[i].dwLocalPort));
                connect.RemoteIP = *new IP(dwordToString(ptTable->table[i].dwRemoteAddr), htons((unsigned short)ptTable->table[i].dwRemotePort));

                tcps.push_back(connect);
            }
        }
        
        return tcps;
    }

    static std::list<Connect> GetUDP()
    {
        std::list<Connect> udps;
        vector<unsigned char> buffer;
        DWORD dwSize = sizeof(MIB_TCPTABLE_OWNER_PID);
        DWORD dwRetValue = 0;

        do {
            buffer.resize(dwSize, 0);
            dwRetValue = GetExtendedUdpTable(buffer.data(), &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        } while (dwRetValue == ERROR_INSUFFICIENT_BUFFER);
        if (dwRetValue == ERROR_SUCCESS)
        {
            PMIB_TCPTABLE_OWNER_PID ptTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(buffer.data());
            for (DWORD i = 0; i < ptTable->dwNumEntries; i++)
            {
                Connect connect;

                connect.protocol = Protocol::TCP;
                connect.PID = ptTable->table[i].dwOwningPid;
                connect.Name = processName(ptTable->table[i].dwOwningPid);
                connect.State = ptTable->table[i].dwState;
                connect.LocalIP = *new IP(dwordToString(ptTable->table[i].dwLocalAddr), htons((unsigned short)ptTable->table[i].dwLocalPort));
                connect.RemoteIP = *new IP(dwordToString(ptTable->table[i].dwRemoteAddr), htons((unsigned short)ptTable->table[i].dwRemotePort));

                udps.push_back(connect);
            }
        }
        
        return udps;
    }

public:
    static std::wstring ToWString(std::string str)
    {
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        std::wstring wide = converter.from_bytes(str);

        return wide;
    }

    static std::string ToString(std::wstring wstr)
    {
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        std::string narrow = converter.to_bytes(wstr);

        return narrow;
    }

    private:
    static char* dupcat(const char* s1, ...) {
        int len;
        char* p, * q, * sn;
        va_list ap;

        len = strlen(s1);
        va_start(ap, s1);
        while (1) {
            sn = va_arg(ap, char*);
            if (!sn)
                break;
            len += strlen(sn);
        }
        va_end(ap);

        p = new char[len + 1];
        strcpy(p, s1);
        q = p + strlen(p);

        va_start(ap, s1);
        while (1) {
            sn = va_arg(ap, char*);
            if (!sn)
                break;
            strcpy(q, sn);
            q += strlen(q);
        }
        va_end(ap);

        return p;
    }

    static char* processName(DWORD id)
    {
        HANDLE processHandle = NULL;
        char filename[MAX_PATH];
        char* ret;

        try
        {
            processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, id);
            if (processHandle != NULL) {
                LPWSTR fileNameW = (wchar_t*)ToWString(filename).c_str();
                if (GetModuleBaseName(processHandle, NULL, fileNameW, sizeof(filename)) == 0) {
                    return (char*)"";
                }
                else {
                    ret = dupcat(filename, 0);
                    return ret;
                }
                CloseHandle(processHandle);
            }
        }
        catch (...)
        {
            return (char*)"";
        }
        return (char*)"";
    }

    static char* dwordToString(DWORD id) {
        char aux[10];
        unsigned long parts[] = { (id & 0xff),(id >> 8) & 0xff,(id >> 16) & 0xff,(id >> 24) & 0xff };
        char* ret = dupcat(_ultoa(parts[0], aux, 10), ".", 0);
        for (int i = 1; i < 4; i++) {
            if (i < 3)
                ret = dupcat(ret, _ultoa(parts[i], aux, 10), ".", 0);
            else
                ret = dupcat(ret, _ultoa(parts[i], aux, 10), 0);
        }
        return ret;
    }

};