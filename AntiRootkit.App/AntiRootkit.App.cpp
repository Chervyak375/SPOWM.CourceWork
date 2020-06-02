#include <chrono>
#include <ctime> 

#include "ProcessorScanner.h"
#include "PortScanner.h"
#include "FSV.h"


int main()
{
	SetConsoleTitle(_T("AntiRootkit"));

	std::list<IScanner*> scanners;
	scanners.push_back((IScanner*)new FSV());
	scanners.push_back((IScanner*)new ProcessorScanner());
	
	std::list<Threat> threats;

	for (auto scanner : scanners)
	{
		auto result = scanner->Scan();
		threats.insert(threats.end(), result.begin(), result.end());
	}

	std::ofstream outfile;
	outfile.open(Helper::GetDate(), std::ios_base::app);

	for (auto threat : threats)
	{
		outfile << ((HiddenProcess*)&threat)->GetFullFileName() << std::endl;
		outfile << ((HiddenProcess*)&threat)->GetPID() << std::endl;
		outfile << Helper::ConvertRiskToString(((HiddenProcess*)&threat)->GetRisk()) << std::endl;

		std::cout << ((HiddenProcess*)&threat)->GetFullFileName() << std::endl;
		std::cout << ((HiddenProcess*)&threat)->GetPID() << std::endl;
		std::cout << Helper::ConvertRiskToString(((HiddenProcess*)&threat)->GetRisk()) << std::endl;
	}

	PortScanner portScanner;
	std::list<BadPort> badPorts;
	
	if (!badPorts.empty())
	{
		outfile << "Opening ports:" << std::endl;
		std::cout << "Opening ports:" << std::endl;
		for (auto badPort : badPorts)
		{
			outfile << Helper::ConvertProtocolToString(badPort.GetProtocol()) << std::endl;
			outfile << badPort.GetPort() << std::endl;
			outfile << Helper::ConvertRiskToString(badPort.GetRisk()) << std::endl;

			std::cout << Helper::ConvertProtocolToString(badPort.GetProtocol()) << std::endl;
			std::cout << badPort.GetPort() << std::endl;
			std::cout << Helper::ConvertRiskToString(badPort.GetRisk()) << std::endl;
		}
	}

	system("pause");
}
