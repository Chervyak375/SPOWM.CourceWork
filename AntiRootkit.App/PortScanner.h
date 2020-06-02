#pragma once

#include <iphlpapi.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <stdlib.h>
#include <errno.h>

#include "BadPort.h"
#include "IScanner.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

class PortScanner : public IScanner
{
public:
	PortScanner() {}

	std::list<Threat> Scan()
	{
		std::list<Threat> badPorts;

		char tcpports[65535];

		PMIB_TCPTABLE pTcpTable;
		DWORD dwSize = 0;
		DWORD dwRetVal = 0;

		int i;

		pTcpTable = (MIB_TCPTABLE*)MALLOC(sizeof(MIB_TCPTABLE));
		if (pTcpTable == NULL) {
			printf("Error allocating memory\n");
			return badPorts;
		}

		dwSize = sizeof(MIB_TCPTABLE);

		printf("Open TCP ports through GetTcpTable()\n\n");

		if ((dwRetVal = GetTcpTable(pTcpTable, &dwSize, TRUE)) == ERROR_INSUFFICIENT_BUFFER) {
			FREE(pTcpTable);
			pTcpTable = (MIB_TCPTABLE*)MALLOC(dwSize);
			if (pTcpTable == NULL) {
				printf("Error allocating memory\n");
				return badPorts;
			}
		}

		if ((dwRetVal = GetTcpTable(pTcpTable, &dwSize, TRUE)) == NO_ERROR) {

			for (i = 0; i < (int)pTcpTable->dwNumEntries; i++) {

				if (pTcpTable->table[i].dwState == MIB_TCP_STATE_LISTEN) {

					printf("%d \n", ntohs((u_short)pTcpTable->table[i].dwLocalPort));

					tcpports[ntohs((u_short)pTcpTable->table[i].dwLocalPort)] = 1;

				}

			}
		}
		else {
			printf("\tGetTcpTable failed with %d\n", dwRetVal);
			FREE(pTcpTable);
			return badPorts;
		}

		if (pTcpTable != NULL) {
			FREE(pTcpTable);
			pTcpTable = NULL;
		}

		printf("\n[*]Searching for Hidden TCP ports through bind() scanning\n\n");

		for (i = 1; i <= 65535; i++) {

			WSADATA wsaData;

			int iResult = 0;

			SOCKET ListenSocket = INVALID_SOCKET;

			struct sockaddr_in service;

			iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
			if (iResult != NO_ERROR) {
				wprintf(L"Error at WSAStartup()\n");
				return badPorts;
			}

			ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (ListenSocket == INVALID_SOCKET) {
				wprintf(L"socket function failed with error: %u\n", WSAGetLastError());
				WSACleanup();
				return badPorts;
			}

			service.sin_family = AF_INET;
			service.sin_addr.s_addr = inet_addr("0.0.0.0");
			service.sin_port = htons(i);

			iResult = bind(ListenSocket, (SOCKADDR*)&service, sizeof(service));
			if (iResult == SOCKET_ERROR) {

				closesocket(ListenSocket);

				int portfind = 0;

				PMIB_TCPTABLE pTcpTable = NULL;
				DWORD dwSize = 0;
				DWORD dwRetVal = 0;

				if ((dwRetVal = GetTcpTable(pTcpTable, &dwSize, TRUE)) == ERROR_INSUFFICIENT_BUFFER) {
					FREE(pTcpTable);
					pTcpTable = (MIB_TCPTABLE*)MALLOC(dwSize);
					if (pTcpTable == NULL) {
						printf("Error allocating memory\n");
						return badPorts;
					}
				}

				if ((dwRetVal = GetTcpTable(pTcpTable, &dwSize, TRUE)) == NO_ERROR) {

					int z;

					for (z = 0; z < (int)pTcpTable->dwNumEntries; z++) {

						if (ntohs((u_short)pTcpTable->table[z].dwLocalPort) == i) {

							portfind = 1;

						}

					}
				}

				if (portfind == 0) {

					badPorts.push_back(*new BadPort(i, Protocol::TCP, Risk::Easy));

				}

			}

			else { closesocket(ListenSocket); }

		}

		// UDP 

		PMIB_UDPTABLE pUdpTable;
		dwSize = 0;
		dwRetVal = 0;

		unsigned short* port_ptr;

		pUdpTable = (MIB_UDPTABLE*)MALLOC(sizeof(MIB_UDPTABLE));
		if (pUdpTable == NULL) {
			printf("Error allocating memory\n");
			return badPorts;
		}

		dwSize = sizeof(MIB_UDPTABLE);

		printf("Open UDP ports through GetUdpTable()\n\n");

		if ((dwRetVal = GetUdpTable(pUdpTable, &dwSize, TRUE)) == ERROR_INSUFFICIENT_BUFFER) {
			FREE(pUdpTable);
			pUdpTable = (MIB_UDPTABLE*)MALLOC(dwSize);
			if (pUdpTable == NULL) {
				printf("Error allocating memory\n");
				return badPorts;
			}
		}

		if ((dwRetVal = GetUdpTable(pUdpTable, &dwSize, TRUE)) == NO_ERROR) {

			for (i = 0; i < pUdpTable->dwNumEntries; i++) {

				port_ptr = (unsigned short*)&pUdpTable->table[i].dwLocalPort;
				printf("%ld\n", htons(*port_ptr));
			}
		}
		else {
			printf("\tGetUdpTable failed with %d\n", dwRetVal);
			FREE(pUdpTable);
			return badPorts;
		}

		if (pUdpTable != NULL) {
			FREE(pUdpTable);
			pUdpTable = NULL;
		}

		printf("\n[*]Searching for Hidden UDP ports through bind() scanning\n\n");

		for (i = 1; i <= 65535; i++) {

			WSADATA wsaData;

			int iResult = 0;

			SOCKET ListenSocket = INVALID_SOCKET;

			struct sockaddr_in service;

			iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
			if (iResult != NO_ERROR) {
				wprintf(L"Error at WSAStartup()\n");
				return badPorts;
			}

			ListenSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (ListenSocket == INVALID_SOCKET) {
				wprintf(L"socket function failed with error: %u\n", WSAGetLastError());
				WSACleanup();
				return badPorts;
			}

			service.sin_family = AF_INET;
			service.sin_addr.s_addr = inet_addr("0.0.0.0");
			service.sin_port = htons(i);

			iResult = bind(ListenSocket, (SOCKADDR*)&service, sizeof(service));

			if (iResult == SOCKET_ERROR) {

				closesocket(ListenSocket);

				int portfind = 0;

				PMIB_UDPTABLE pUdpTable = NULL;
				dwSize = 0;
				dwRetVal = 0;

				unsigned short* port_ptr;

				if ((dwRetVal = GetUdpTable(pUdpTable, &dwSize, TRUE)) == ERROR_INSUFFICIENT_BUFFER) {
					FREE(pUdpTable);
					pUdpTable = (MIB_UDPTABLE*)MALLOC(dwSize);
					if (pUdpTable == NULL) {
						printf("Error allocating memory\n");
						return badPorts;
					}
				}

				if ((dwRetVal = GetUdpTable(pUdpTable, &dwSize, TRUE)) == NO_ERROR) {

					int z;

					for (z = 0; z < pUdpTable->dwNumEntries; z++) {

						port_ptr = (unsigned short*)&pUdpTable->table[z].dwLocalPort;

						if (htons(*port_ptr) == i) {

							portfind = 1;
						}
					}
				}

				if (portfind == 0) {

					badPorts.push_back(*new BadPort(i, Protocol::UDP, Risk::Easy));

				}

			}

			else { closesocket(ListenSocket); }

		}

		auto tcps = Helper::GetTCP();
		auto udps = Helper::GetUDP();
		std::list<Connect> connects;
		connects.insert(connects.end(), tcps.begin(), tcps.end());
		connects.insert(connects.end(), udps.begin(), udps.end());

		std::list<Threat> result;

		for (auto badPort : badPorts)
			for (auto connect : connects)
				if (connect.LocalIP.Port == ((BadPort*)&badPort)->GetPort())
				{
					result.push_back(*(Threat*)new HiddenProcess(connect.PID));

					/* std::cout << connect.PID << std::endl;
					std::cout << connect.Name << std::endl;
					std::cout << connect.State << std::endl;
					std::cout << connect.LocalIP.ToString() << std::endl;
					std::cout << connect.RemoteIP.ToString() << std::endl;
					std::cout << std::endl; */
				}

		return result;
}

};