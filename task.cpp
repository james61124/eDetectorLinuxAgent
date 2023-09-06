#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <string>
#include <cstring>
#include <future>
#include <thread>

#include "task.h"



Task::Task(Info* infoInstance, SocketSend* socketSendInstance) {

	// handshake
    functionMap["GiveInfo"] = std::bind(&Task::GiveInfo, this);
    // functionMap["GiveDriveInfo"] = std::bind(&Task::GiveDriveInfo, this);

	// functionMap["DetectProcess"] = std::bind(&Task::DetectProcess_, this);

    // // packet from server
    // functionFromServerMap["OpenCheckthread"] = &Task::OpenCheckthread;
    // functionFromServerMap["UpdateDetectMode"] = &Task::UpdateDetectMode;

	// // Scan
	// functionFromServerMap["GetScan"] = &Task::GetScan;
	// functionMap["GiveProcessData"] = std::bind(&Task::GiveProcessData, this);
	

	// // Explorer
    // functionFromServerMap["GetDrive"] = &Task::GetDrive; // ExplorerInfo_
	// functionFromServerMap["ExplorerInfo"] = &Task::ExplorerInfo_;

	// // Collect
	// functionMap["CollectionComputerInfo"] = std::bind(&Task::CollectionComputerInfo, this);
    // functionFromServerMap["GetCollectInfo"] = &Task::GetCollectInfo;
    // functionFromServerMap["DataRight"] = &Task::DataRight;

    info = infoInstance;
    socketsend = socketSendInstance;
}

// handshake
int Task::GiveInfo() {
    // getSystemInfo();
	char* functionName = new char[24];
	strcpy(functionName, "GiveInfo");
	char* buffer = new char[STRINGMESSAGELEN];

	// char* SysInfo = tool.GetSysInfo();
	// char* OsStr = GetOSVersion();
	// char* cComputerName = tool.GetComputerNameUTF8();
	// char* cUserName = tool.GetUserNameUTF8();
	// unsigned long long BootTime = tool.GetBootTime();

	char* SysInfo = new char[36];
	char* OsStr = new char[36];
	char* cComputerName = new char[36];
	char* cUserName = new char[36];
	unsigned long long BootTime = 0;
	long long m_DigitalSignatureHash = 0;
	
	// key
	char* KeyNum = new char[36];

	// file version
	char* FileVersion = new char[64];
	snprintf(buffer, STRINGMESSAGELEN, "%s|%s|%s|%s|%s,%d,%d|%d|%s|%lu", SysInfo, OsStr, cComputerName, cUserName, FileVersion, info->Port, info->DetectPort, BootTime, KeyNum, m_DigitalSignatureHash);
    
    return socketsend->SendMessageToServer(functionName, buffer);
}
int Task::OpenCheckthread(StrPacket* udata) {

	printf("store key into registry\n");
	if (strcmp(udata->csMsg, "null")) {
		strcpy(info->UUID, udata->csMsg);
		// WriteRegisterValue(udata->csMsg);
	}

	std::thread CheckConnectThread([&]() { CheckConnect(); });
	CheckConnectThread.detach();

	// strcpy(UUID,udata->csMsg);
	// GiveDetectInfoFirst();

	//std::future<int> CheckConnectThread = std::async(&Task::CheckConnect, this);
	//CheckConnectThread.get();

	 //std::thread CheckConnectThread(&Task::CheckConnect, this);
	 //CheckConnectThread.join();

	// store key into registry

	return GiveDetectInfoFirst();

}
int Task::GiveDetectInfoFirst() {
	char* buff = new char[STRINGMESSAGELEN];
	char* functionName = new char[24];
	strcpy(functionName, "GiveDetectInfoFirst");
	snprintf(buff, STRINGMESSAGELEN, "%d|%d", info->DetectProcess, info->DetectNetwork);
	return socketsend->SendMessageToServer(functionName, buff);
}
int Task::UpdateDetectMode(StrPacket* udata) {

	std::vector<std::string>DetectMode = tool.SplitMsg(udata->csMsg);
	for (int i = 0; i < DetectMode.size(); i++) {
		if (i == 0) info->DetectProcess = DetectMode[i][0] - '0';
		else if (i == 1) info->DetectNetwork = DetectMode[i][0] - '0';
		else printf("UpdateDetectMode parse failed\n");
	}

	if (info->DetectProcess) {
		int DetectProcessPid = 0;

		// run detect process

		info->processMap["DetectProcess"] = DetectProcessPid;
		log.logger("Debug", "DetectProcess enabled");
	}
	else {
		auto it = info->processMap.find("DetectProcess");
		if (it != info->processMap.end() && it->second != 0 ) {
			// kill detect process
		}
	}

	if (info->DetectNetwork) {
		int DetectNetworkPid = 0;
		// run detect network

		info->processMap["DetectNetwork"] = DetectNetworkPid;
		log.logger("Debug", "DetectNetwork enabled");
	}
	else {
		auto it = info->processMap.find("DetectNetwork");
		if (it != info->processMap.end() && it->second != 0) {
			// kill detect process
		}
	}

	return GiveDetectInfo();

}
int Task::GiveDetectInfo() {
	char* buff = new char[STRINGMESSAGELEN];
	char* functionName = new char[24];
	strcpy(functionName, "GiveDetectInfo");
	snprintf(buff, STRINGMESSAGELEN, "%d|%d", info->DetectProcess, info->DetectNetwork);
	int ret = socketsend->SendMessageToServer(functionName, buff);

	// network
	//DWORD MyPid = GetCurrentProcessId();
	//DetectNewNetwork(MyPid);

	// test
	//GiveProcessData();
	//DetectProcess_();
	//CollectionComputerInfo();
	//GiveDriveInfo();

	//char Drive[2];
	//char FileSystem[20];
	//strcpy_s(Drive, 2, "C");
	//strcpy_s(FileSystem, 20, "NTFS");
	//GiveExplorerData(Drive, FileSystem);

	//StrPacket* tmp = new StrPacket;
	//GetScan(tmp);

	return ret;
}
int Task::CheckConnect() {

     while(true){
		 char* functionName = new char[24];
		 strcpy(functionName, "CheckConnect");
		 char* null = new char[1];
		 strcpy(null, "");
         if (!socketsend->SendMessageToServer(functionName, null)) {
             printf("CheckConnect sent failed\n");
         } else {
         }
		 std::this_thread::sleep_for(std::chrono::seconds(30));
     }

    // to do
    // check kill time

    return 0;
}

// // detect
// int Task::DetectProcessRisk(int pMainProcessid, bool IsFirst, set<DWORD>* pApiName, SOCKET* tcpSocket)
// {
// 	Log log;
// 	MemProcess* m_MemPro = new MemProcess;
// 	TCHAR* MyPath = new TCHAR[MAX_PATH_EX];
// 	GetModuleFileName(GetModuleHandle(NULL), MyPath, MAX_PATH_EX);
// 	clock_t start, end;
// 	clock_t m_BootStart, m_BootEnd;
// 	m_MemPro->m_RiskArray1.clear();
// 	m_MemPro->m_RiskArray2.clear();
// 	m_MemPro->m_UnKnownData1.clear();
// 	m_MemPro->m_UnKnownData2.clear();
// 	m_MemPro->pRiskArray = &m_MemPro->m_RiskArray1;
// 	m_MemPro->RiskArrayNum = 1;
// 	m_MemPro->pUnKnownData = &m_MemPro->m_UnKnownData1;
// 	m_MemPro->UnKnownDataNum = 1;

// 	//char* cBootTime = CStringToCharArray(pBootTime, CP_UTF8);
// 	bool IsWin10 = false;
// 	char* OSstr = GetOSVersion();
// 	if ((strstr(OSstr, "Windows 10") != 0) || (strstr(OSstr, "Windows Server 2016") != 0))
// 		IsWin10 = true;
// 	map<DWORD, process_info_Ex> StartProcessID;
// 	map<DWORD, process_info_Ex> NewProcessID;
// 	map<DWORD, process_info_Ex>::iterator st;
// 	map<DWORD, process_info_Ex>::iterator nt;

// 	//map<DWORD,process_info_Ex>::iterator ft;
// 	//printf("load now process info start\n");
// 	m_MemPro->LoadNowProcessInfoDetect(&StartProcessID);
// 	//printf("load now process info end\n");
// 	//if (IsFirst)
// 	//{
// 	printf("detecting current process...\n");
// 	log.logger("Info", "detect current process...");
// 	for (st = StartProcessID.begin(); st != StartProcessID.end(); st++)
// 	{
// 		if (!m_MemPro->IsWindowsProcessNormal(&StartProcessID, st->first))
// 		{
// 			//log.logger("Debug", "detecting current process...");
// 			m_MemPro->ParserProcessRisk(&st->second, pApiName, MyPath, m_MemPro->pUnKnownData);
// 		}
// 	}
// 	printf("detect current process finished\n");
// 	log.logger("Info", "detecting current finished");

// 	start = clock();
// 	m_BootStart = clock();
// 	m_BootEnd = clock();

// 	for (;;)
// 	{
// 		printf("detecting...\n");
// 		NewProcessID.clear();
// 		m_MemPro->LoadNowProcessInfoDetect(&NewProcessID);

// 		for (nt = NewProcessID.begin(); nt != NewProcessID.end(); nt++)
// 		{
// 			st = StartProcessID.find(nt->first);
// 			if (st == StartProcessID.end())
// 			{
// 				m_MemPro->ParserProcessRisk(&nt->second, pApiName, MyPath, m_MemPro->pUnKnownData); // LoadAutoRunStartCommand
// 			}
// 		}
// 		end = clock();


// 		if ((end - start) > 20000)
// 		{
// 			if (!m_MemPro->pRiskArray->empty())
// 			{
// 				if (m_MemPro->RiskArrayNum == 1)
// 				{
// 					m_MemPro->ChangeRiskArrayNum(1);
// 					vector<ProcessInfoData>* pRiskArray = m_MemPro->GetRiskArray1();
// 					if (!pRiskArray->empty())
// 					{
// 						SendProcessDataToServer(pRiskArray, tcpSocket);
// 					}
// 					//if (m_MemPro->UnKnownDataNum == 1)
// 					//{
// 					//	vector<UnKnownDataInfo>* pUnKnownData = m_MemPro->GetUnKnownData1();
// 					//	if (!pUnKnownData->empty())
// 					//	{
// 					//		m_MemPro->ChangeUnKnownDataNum(1);
// 					//		m_MemPro->SendUnKnownDataToServer(pUnKnownData);
// 					//		pUnKnownData->clear();
// 					//	}
// 					//}
// 					//int ret = socketsend->SendMessageToServer(functionName_GiveDetectProcess, End);
// 					pRiskArray->clear();
// 				}
// 				else if (m_MemPro->RiskArrayNum == 2)
// 				{
// 					m_MemPro->ChangeRiskArrayNum(2);
// 					vector<ProcessInfoData>* pRiskArray = m_MemPro->GetRiskArray2();
// 					if (!pRiskArray->empty())
// 					{
// 						SendProcessDataToServer(pRiskArray, tcpSocket);
// 					}
// 					//if (m_MemPro->UnKnownDataNum == 2)
// 					//{
// 					//	vector<UnKnownDataInfo>* pUnKnownData = m_MemPro->GetUnKnownData2();
// 					//	if (!pUnKnownData->empty())
// 					//	{
// 					//		m_MemPro->ChangeUnKnownDataNum(2);
// 					//		SendUnKnownDataToServer(pUnKnownData);
// 					//		pUnKnownData->clear();
// 					//	}
// 					//}
// 					//int ret = socketsend->SendMessageToServer(functionName_GiveDetectProcess, End);
// 					pRiskArray->clear();
// 				}
// 			}
// 			//if(!pUnKnownData->empty())
// 			//{
// 			//}
// 			start = clock();
// 		}
// 		StartProcessID.clear();
// 		StartProcessID = NewProcessID;
// 		if (!IsHavePID(pMainProcessid))
// 			break;
// 		if (IsWin10)
// 		{
// 			if ((m_BootEnd - m_BootStart) > 60000)
// 				Sleep(200);
// 			else
// 			{
// 				m_BootEnd = clock();
// 				Sleep(10);
// 			}
// 		}
// 		else
// 		{
// 			if ((m_BootEnd - m_BootStart) > 60000)
// 				Sleep(50);
// 			else
// 			{
// 				m_BootEnd = clock();
// 				Sleep(10);
// 			}
// 		}
// 	}
// 	NewProcessID.clear();
// 	StartProcessID.clear();
// 	m_MemPro->m_RiskArray1.clear();
// 	m_MemPro->m_RiskArray2.clear();
// 	delete[] MyPath;
// 	return 1;
// }
// void Task::SendProcessDataToServer(vector<ProcessInfoData>* pInfo, SOCKET* tcpSocket)
// {
// 	char* functionName_GiveDetectProcessFrag = new char[24];
// 	strcpy_s(functionName_GiveDetectProcessFrag, 24, "GiveDetectProcessFrag");

// 	char* TempStr = new char[DATASTRINGMESSAGELEN];
// 	vector<ProcessInfoData>::iterator it;

// 	for (it = pInfo->begin(); it != pInfo->end(); it++)
// 	{
// 		if (_tcscmp((*it).ProcessHash, _T("null"))) {
// 			wchar_t* wTempStr = new wchar_t[DATASTRINGMESSAGELEN];

// 			// command line
// 			HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (*it).ProcessID);
// 			MemProcess* m_MemPro = new MemProcess;
// 			TCHAR* Comstr = new TCHAR[MAX_PATH_EX];
// 			DWORD ret1 = m_MemPro->GetRemoteCommandLineW(processHandle, Comstr, MAX_PATH_EX);
// 			if (ret1 == 0) _tcscpy_s(Comstr, MAX_PATH_EX, _T(""));
// 			CloseHandle(processHandle);

// 			printf("find parent name\n");
// 			TCHAR* ParentName = new TCHAR[MAX_PATH];
// 			swprintf_s(ParentName, MAX_PATH, L"%s", "null");
// 			NTSTATUS status;
// 			PVOID buffer;
// 			PSYSTEM_PROCESS_INFO spi;
// 			buffer = VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
// 			if (!buffer) printf("failed to allocate for buffer\n");
// 			spi = (PSYSTEM_PROCESS_INFO)buffer;
// 			if (!NT_SUCCESS(status = NtQuerySystemInformation(SystemProcessInformation, spi, 1024 * 1024, NULL))) VirtualFree(buffer, 0, MEM_RELEASE);
// 			while (spi->NextEntryOffset) {
// 				if ((*it).ParentID == (int)spi->ProcessId) {
// 					swprintf_s(ParentName, MAX_PATH, L"%s", spi->ImageName.Buffer);
// 				}
// 				spi = (PSYSTEM_PROCESS_INFO)((LPBYTE)spi + spi->NextEntryOffset);
// 			}


// 			int Service = 0, AutoRun = 0;
// 			if ((*it).StartRun == 1) {
// 				Service = 1;
// 			}
// 			else if ((*it).StartRun == 2) {
// 				AutoRun = 1;
// 			}
// 			else if ((*it).StartRun == 3) {
// 				Service = 1;
// 				AutoRun = 1;
// 			}

// 			swprintf_s(wTempStr, DATASTRINGMESSAGELEN, L"%s|%s|%s|%s|%s|%ld|%s|%s|%s|%ld|%d,%d|%d|%d,%d|%d,%d"
// 				, (*it).ProcessName, (*it).ProcessCTime, Comstr, (*it).ProcessHash, (*it).ProcessPath,
// 				(*it).ParentID, ParentName, (*it).ParentPath, (*it).SignerSubjectName, (*it).ProcessID, (*it).InjectionPE, (*it).InjectionOther
// 				, (*it).Injected, Service, AutoRun, (*it).HideProcess, (*it).HideAttribute
// 			); // remove ParentName 

// 			char* cTempStr = CStringToCharArray(wTempStr, CP_UTF8);
// 			strcpy_s(TempStr, DATASTRINGMESSAGELEN, cTempStr);

// 			int ret = 1;

// 			// abnormal dll
// 			if (!(*it).Abnormal_dll.empty())
// 			{
// 				strcat_s(TempStr, DATASTRINGMESSAGELEN, "|");
// 				set<string>::iterator dllit;
// 				for (dllit = (*it).Abnormal_dll.begin(); dllit != (*it).Abnormal_dll.end(); dllit++)
// 				{
// 					char* dllstr = new char[4096];
// 					sprintf_s(dllstr, 4096, "%s;", (*dllit).c_str());
// 					if ((strlen(dllstr) + strlen(TempStr)) >= DATASTRINGMESSAGELEN)
// 					{
// 						ret = GiveDetectProcessFrag(TempStr, tcpSocket);
// 						memset(TempStr, '\0', DATASTRINGMESSAGELEN);
// 						if (ret <= 0)
// 						{
// 							delete[] dllstr;
// 							break;
// 						}
// 					}
// 					strcat_s(TempStr, DATASTRINGMESSAGELEN, dllstr);
// 					delete[] dllstr;
// 				}
// 				if (ret <= 0)
// 					break;
// 			}
// 			else
// 				strcat_s(TempStr, DATASTRINGMESSAGELEN, "|null");

// 			// inline hook
// 			if (!(*it).InlineHookInfo.empty())
// 			{
// 				strcat_s(TempStr, DATASTRINGMESSAGELEN, "|");
// 				set<string>::iterator Inlineit;
// 				for (Inlineit = (*it).InlineHookInfo.begin(); Inlineit != (*it).InlineHookInfo.end(); Inlineit++)
// 				{
// 					char* Inlinestr = new char[4096];
// 					sprintf_s(Inlinestr, 4096, "%s;", (*Inlineit).c_str());
// 					if ((strlen(Inlinestr) + strlen(TempStr)) >= DATASTRINGMESSAGELEN)
// 					{
// 						ret = GiveDetectProcessFrag(TempStr, tcpSocket);
// 						memset(TempStr, '\0', DATASTRINGMESSAGELEN);
// 						if (ret <= 0)
// 						{
// 							delete[] Inlinestr;
// 							break;
// 						}
// 					}
// 					strcat_s(TempStr, DATASTRINGMESSAGELEN, Inlinestr);
// 					delete[] Inlinestr;
// 				}
// 				if (ret <= 0)
// 					break;
// 			}
// 			else
// 				strcat_s(TempStr, DATASTRINGMESSAGELEN, "|null");


// 			ret = GiveDetectProcess(TempStr, tcpSocket);
// 			if (ret <= 0) break;
// 			else memset(TempStr, '\0', DATASTRINGMESSAGELEN);

// 			delete[] m_MemPro;
// 			delete[] Comstr;
// 			delete[] cTempStr;
// 			delete[] wTempStr;
// 		}
		
// 	}
// 	delete[] TempStr;



// 	/*senddatamsgtoserver(mymac,myip,"givedetectprocessend","end");
// 	pinfo->clear();*/
// }
// int Task::DetectProcess_() {

// 	printf("sending DetectProcess\n");
// 	MemProcess* m_MemPro = new MemProcess;
// 	set<DWORD> m_ApiName;
// 	tool.LoadApiPattern(&m_ApiName);
// 	DWORD pMainProcessid = GetCurrentProcessId();

// 	try {
// 		DetectProcessRisk(pMainProcessid, false, &m_ApiName, info->tcpSocket);
// 	}
// 	catch (...) {}

// 	m_ApiName.clear();
// 	delete m_MemPro;
// 	return 1;
// }
// int Task::DetectNewNetwork(int pMainProcessid) {
// 	char* functionName = new char[24];
// 	strcpy_s(functionName, 24, "GiveDetectNetwork");

// 	MemProcess* m_MemPro = new MemProcess;

// 	TCHAR* MyPath = new TCHAR[MAX_PATH_EX];
// 	GetModuleFileName(GetModuleHandle(NULL), MyPath, MAX_PATH_EX);
// 	clock_t start, end;
// 	time_t NetworkClock;
// 	m_MemPro->m_NetworkHistory1.clear();
// 	m_MemPro->m_NetworkHistory2.clear();
// 	m_MemPro->pNetworkHistory = &m_MemPro->m_NetworkHistory1;
// 	m_MemPro->NetworkHistoryNum = 1;

// 	//pNetworkHistory->push_back(m_HandStr);
// 	set<u_short> m_ListenPort;
// 	map<wstring, u_short> StartNetworkInfo;
// 	map<wstring, u_short> NewNetworkInfo;
// 	map<wstring, u_short>::iterator nst;
// 	map<wstring, u_short>::iterator nnt;
// 	set<u_short>::iterator lt;
// 	char* OSstr = GetOSVersion();
// 	if ((strstr(OSstr, "Windows XP") != 0) || (strstr(OSstr, "Windows Server 2003") != 0))
// 		GetDetectTcpInformationXP(&StartNetworkInfo, &m_ListenPort);
// 	else
// 		GetDetectTcpInformation(&StartNetworkInfo, &m_ListenPort);

// 	time(&NetworkClock);
// 	for (nst = StartNetworkInfo.begin();nst != StartNetworkInfo.end();nst++)
// 	{
// 		DWORD m_Pid = m_MemPro->GetInfoPid(/*(*nst).c_str()*/nst->first.c_str());
// 		if (m_Pid != 0)
// 		{
// 			TCHAR* m_NetworkStr = new TCHAR[2048];
// 			TCHAR* m_Path = new TCHAR[512];
// 			//TCHAR * m_ComStr = new TCHAR[512];
// 			time_t m_Time = 0;
// 			//TCHAR * m_UserName = new TCHAR[_MAX_FNAME];
// 			_tcscpy_s(m_Path, 512, _T("null"));
// 			//_tcscpy_s(m_ComStr,512,_T("null"));
// 			//_tcscpy_s(m_Time,20,_T("null"));
// 			//_tcscpy_s(m_UserName,_MAX_FNAME,_T("null"));
// 			//GetProcessInfo(m_Pid,m_Path,m_Time,m_UserName,m_ComStr);
// 			m_MemPro->GetProcessOnlyPathAndTime(m_Pid, m_Path, m_Time);
// 			if (_tcsicmp(m_Path, MyPath))
// 			{
// 				int ConnectionINorOUT = 0;
// 				lt = m_ListenPort.find(nst->second);
// 				if (lt != m_ListenPort.end())
// 					ConnectionINorOUT = 1;
// 				swprintf_s(m_NetworkStr, 2048, _T("%s|%lld|%lld|%d|%u\n"), nst->first.c_str(), NetworkClock, m_Time, ConnectionINorOUT, nst->second);
// 				char* cNetworkStr = CStringToCharArray(m_NetworkStr, CP_UTF8);
// 				char m_WriteStr[2048];
// 				sprintf_s(m_WriteStr, 2048, "%s", cNetworkStr);
// 				if (m_MemPro->pNetworkHistory->size() >= 3000000)
// 				{
// 					m_MemPro->pNetworkHistory->erase(m_MemPro->pNetworkHistory->begin());
// 					m_MemPro->pNetworkHistory->push_back(m_WriteStr);
// 				}
// 				else
// 					m_MemPro->pNetworkHistory->push_back(m_WriteStr);
// 				delete[] cNetworkStr;
// 			}
// 			//delete [] m_UserName;
// 			//delete [] m_Time;
// 			//delete [] m_ComStr;
// 			delete[] m_Path;
// 			delete[] m_NetworkStr;
// 		}
// 	}
// 	start = clock();
// 	for (;;)
// 	{
// 		m_ListenPort.clear();
// 		NewNetworkInfo.clear();
// 		if ((strstr(OSstr, "Windows XP") != 0) || (strstr(OSstr, "Windows Server 2003") != 0))
// 			GetDetectTcpInformationXP(&NewNetworkInfo, &m_ListenPort);
// 		else
// 			GetDetectTcpInformation(&NewNetworkInfo, &m_ListenPort);

// 		time(&NetworkClock);
// 		for (nnt = NewNetworkInfo.begin();nnt != NewNetworkInfo.end();nnt++)
// 		{
// 			nst = StartNetworkInfo.find(nnt->first.c_str());
// 			if (nst == StartNetworkInfo.end())
// 			{
// 				DWORD m_Pid = m_MemPro->GetInfoPid(nnt->first.c_str());
// 				if (m_Pid != 0)
// 				{
// 					TCHAR* m_NetworkStr = new TCHAR[2048];
// 					TCHAR* m_Path = new TCHAR[512];
// 					//TCHAR * m_ComStr = new TCHAR[512];
// 					time_t m_Time = 0;
// 					//TCHAR * m_UserName = new TCHAR[_MAX_FNAME];
// 					_tcscpy_s(m_Path, 512, _T("null"));
// 					//_tcscpy_s(m_ComStr,512,_T("null"));
// 					//_tcscpy_s(m_Time,20,_T("null"));
// 					//_tcscpy_s(m_UserName,_MAX_FNAME,_T("null"));
// 					m_MemPro->GetProcessOnlyPathAndTime(m_Pid, m_Path, m_Time);
// 					if (_tcsicmp(m_Path, MyPath))
// 					{
// 						int ConnectionINorOUT = 0;
// 						lt = m_ListenPort.find(nnt->second);
// 						if (lt != m_ListenPort.end())
// 							ConnectionINorOUT = 1;
// 						swprintf_s(m_NetworkStr, 2048, _T("%s|%lld|%lld|%d|%u\n"), nnt->first.c_str(), NetworkClock, m_Time, ConnectionINorOUT, nnt->second);
// 						char* cNetworkStr = CStringToCharArray(m_NetworkStr, CP_UTF8);
// 						char m_WriteStr[2048];
// 						sprintf_s(m_WriteStr, 2048, "%s", cNetworkStr);
// 						if (m_MemPro->pNetworkHistory->size() >= 3000000)
// 						{
// 							m_MemPro->pNetworkHistory->erase(m_MemPro->pNetworkHistory->begin());
// 							m_MemPro->pNetworkHistory->push_back(m_WriteStr);
// 						}
// 						else
// 							m_MemPro->pNetworkHistory->push_back(m_WriteStr);
// 						delete[] cNetworkStr;
// 					}
// 					//delete [] m_UserName;
// 					//delete [] m_Time;
// 					//delete [] m_ComStr;
// 					delete[] m_Path;
// 					delete[] m_NetworkStr;
// 				}
// 			}
// 		}
// 		end = clock();
// 		if ((end - start) > 30000)
// 		{
// 			if (!m_MemPro->pNetworkHistory->empty())
// 			{
// 				if (m_MemPro->NetworkHistoryNum == 1)
// 				{
// 					m_MemPro->ChangeNetworkHistoryNum(1);
// 					vector<string>* pNetworkHistory = m_MemPro->GetNetworkHistory1();
// 					if (!pNetworkHistory->empty())
// 					{
// 						SendNetworkDetectToServer(pNetworkHistory);
// 					}

// 				}
// 				else if (m_MemPro->NetworkHistoryNum == 2)
// 				{
// 					m_MemPro->ChangeNetworkHistoryNum(2);
// 					vector<string>* pNetworkHistory = m_MemPro->GetNetworkHistory2();
// 					if (!pNetworkHistory->empty())
// 					{
// 						SendNetworkDetectToServer(pNetworkHistory);
// 					}

// 				}
// 			}
// 			start = clock();
// 		}
// 		StartNetworkInfo.clear();
// 		StartNetworkInfo = NewNetworkInfo;
// 		if (!IsHavePID(pMainProcessid))
// 			break;
// 		Sleep(100);
// 	}
// 	m_ListenPort.clear();
// 	NewNetworkInfo.clear();
// 	StartNetworkInfo.clear();
// 	m_MemPro->m_NetworkHistory1.clear();
// 	m_MemPro->m_NetworkHistory2.clear();
// 	delete[] MyPath;

// 	return 1;
// }
// void Task::SendNetworkDetectToServer(vector<string>* pInfo)
// {
// 	int m_Count = 0;
// 	int ret = 1;
// 	char* TmpSend = new char[DATASTRINGMESSAGELEN];
// 	memset(TmpSend, '\0', DATASTRINGMESSAGELEN);

// 	vector<string>::iterator it;
// 	for (it = pInfo->begin();it != pInfo->end();it++)
// 	{
// 		if ((*it).size() >= DATASTRINGMESSAGELEN)
// 			continue;
// 		int TmpSize = (int)strlen(TmpSend);
// 		if ((TmpSize + (int)(*it).size()) >= DATASTRINGMESSAGELEN)
// 		{
// 			ret = GiveDetectNetwork(TmpSend, info->tcpSocket);
// 			if (ret <= 0)
// 				break;
// 			else
// 				memset(TmpSend, '\0', DATASTRINGMESSAGELEN);
// 		}
// 		strcat_s(TmpSend, DATASTRINGMESSAGELEN, (*it).c_str());
// 	}

// 	if (ret > 0)
// 	{
// 		ret = GiveDetectNetwork(TmpSend, info->tcpSocket);
// 		pInfo->clear();
// 	}
	
// 	delete[] TmpSend;
// }

// int Task::GiveDetectProcess(char* buff, SOCKET* tcpSocket) {
// 	char* functionName = new char[24];
// 	strcpy_s(functionName, 24, "GiveDetectProcess");
// 	return socketsend->SendDataToServer(functionName, buff, tcpSocket);
// }
// int Task::GiveDetectProcessFrag(char* buff, SOCKET* tcpSocket) {
// 	char* functionName = new char[24];
// 	strcpy_s(functionName, 24, "GiveDetectProcessFrag");
// 	return socketsend->SendDataToServer(functionName, buff, tcpSocket);
// }
// int Task::GiveDetectNetwork(char* buff, SOCKET* tcpSocket) {
// 	char* functionName = new char[24];
// 	strcpy_s(functionName, 24, "GiveDetectNetwork");
// 	return socketsend->SendDataToServer(functionName, buff, tcpSocket);
// }


// // scan
// int Task::GetScan(StrPacket* udata) {

// 	//SOCKET* tcpSocket = CreateNewSocket();
// 	//if (tcpSocket == nullptr) return 0;

// 	//int ret = GiveProcessData(tcpSocket);
// 	//closesocket(*tcpSocket);

// 	DWORD m_ScanProcessPid = 0;
// 	TCHAR* RunExeStr = new TCHAR[MAX_PATH];
// 	TCHAR* RunComStr = new TCHAR[512];
// 	GetModuleFileName(GetModuleHandle(NULL), RunExeStr, MAX_PATH);

// 	//TCHAR MyName[MAX_PATH];
// 	//swprintf_s(MyName, MAX_PATH, L"%hs", "./Agent_VS2019");
// 	wstring filename = tool.GetFileName();
// 	TCHAR MyName[MAX_PATH];
// 	wcscpy_s(MyName, filename.c_str());

// 	TCHAR ServerIP[MAX_PATH];
// 	swprintf_s(ServerIP, MAX_PATH, L"%hs", info->ServerIP);

// 	swprintf_s(RunComStr, 512, L"\"%s\" %s %d Scan", MyName, ServerIP, info->Port);
// 	wprintf(L"Run Process: %ls\n", RunComStr);
// 	RunProcessEx(RunExeStr, RunComStr, 1024, FALSE, FALSE, m_ScanProcessPid);

// 	info->processMap["Scan"] = m_ScanProcessPid;
// 	log.logger("Debug", "Scan enabled");

// 	return 1;

// }
// int Task::GiveProcessData() {
// 	char* Scan = new char[5];
// 	strcpy_s(Scan, 5, "Scan");

//     std::set<DWORD> m_ApiName;
//     tool.LoadApiPattern(&m_ApiName);
//     std::map<DWORD, ProcessInfoData> m_ProcessInfo;
//     std::vector<UnKnownDataInfo> m_UnKnownData;

// 	printf("start scan...\n");
//     ScanRunNowProcess(this, &m_ProcessInfo, &m_ApiName, &m_UnKnownData, info->tcpSocket);
// 	printf("finish scan...\n");

// 	if (!m_ProcessInfo.empty()) {
// 		try {
// 			GiveScanDataSendServer(info->MAC, info->IP, Scan, &m_ProcessInfo, &m_UnKnownData, info->tcpSocket);
// 		}
// 		catch (...) {
// 			printf("GiveScanDataSendServer has failed.\n");
// 		}
		
// 	}

//     m_UnKnownData.clear();
//     m_ProcessInfo.clear();
//     m_ApiName.clear();
//     int ret = 1;
//     return ret;

// }
// void Task::ScanRunNowProcess(void* argv, map<DWORD, ProcessInfoData>* pInfo, set<DWORD>* pApiName, vector<UnKnownDataInfo>* pMembuf, SOCKET* tcpSocket)
// {
// 	MemProcess* m_MemPro = new MemProcess;
// 	map<DWORD, process_info_Ex> process_list;
// 	m_MemPro->LoadNowProcessInfo(&process_list);
// 	vector<TCPInformation> NetInfo;
// 	char* OSstr = GetOSVersion();

// 	if ((strstr(OSstr, "Windows XP") != 0) || (strstr(OSstr, "Windows Server 2003") != 0)) GetTcpInformationXPEx(&NetInfo);
// 	else if (strstr(OSstr, "Windows 2000") != 0) {}
// 	else GetTcpInformationEx(&NetInfo);
// 	delete[] OSstr;
// 	time_t NetworkClock;
// 	time(&NetworkClock);
// 	//int ret = m_Client->SendDataMsgToServer(m_Client->MyMAC, m_Client->MyIP, "GiveScanProgress", "10");

// 	map<wstring, BOOL> m_ServiceRun;
// 	set<wstring> m_StartRun;
// 	AutoRun* m_AutoRun = new AutoRun;
// 	printf("LoadServiceStartCommand\n");
// 	m_AutoRun->LoadServiceStartCommand(&m_ServiceRun);
// 	printf("LoadAutoRunStartCommand\n");
// 	m_AutoRun->LoadAutoRunStartCommand(&m_StartRun);
// 	//MessageBox(0,L"168",0,0);
// 	//if (ret > 0)
// 	//{

// 	int InfoSize = (int)process_list.size();
// 	int InfoCount = 0;
// 	map<DWORD, process_info_Ex>::iterator pt;

// 	char* buff = new char[DATASTRINGMESSAGELEN];
// 	sprintf_s(buff, DATASTRINGMESSAGELEN, "%d", InfoSize);
// 	int ret = GiveScanInfo(buff, tcpSocket);
// 	if (!ret) {
// 		printf("GiveScanInfo send failed\n");
// 		return;
// 	}
// 	delete[] buff;


// 	for (pt = process_list.begin(); pt != process_list.end(); pt++, InfoCount++)
// 	{
// 		printf("%d/%d\n", InfoCount, InfoSize);
// 		char* Progress = new char[DATASTRINGMESSAGELEN];
// 		sprintf_s(Progress, DATASTRINGMESSAGELEN, "%d/%d", InfoCount, InfoSize);
// 		GiveScanProgress(Progress, tcpSocket);
// 		delete[] Progress;

// 		if (!m_MemPro->IsWindowsProcessNormal(&process_list, pt->first))
// 		{
// 			ProcessInfoData m_Info;
// 			m_Info.HideAttribute = FALSE;
// 			m_Info.HideProcess = pt->second.IsHide;
// 			lstrcpy(m_Info.ProcessName, pt->second.process_name);
// 			_tcscpy_s(m_Info.ProcessPath, MAX_PATH_EX, pt->second.process_Path);
// 			//memset(m_Info.ProcessTime,'\0',20);
// 			_tcscpy_s(m_Info.ProcessTime, 20, _T("null"));
// 			_tcscpy_s(m_Info.ProcessCTime, 20, _T("null"));
// 			_tcscpy_s(m_Info.ParentCTime, 20, _T("null"));
// 			if (pt->second.ProcessCreateTime > 0)
// 				swprintf_s(m_Info.ProcessCTime, 20, _T("%llu"), pt->second.ProcessCreateTime);
// 			if (pt->second.parentCreateTime > 0)
// 				swprintf_s(m_Info.ParentCTime, 20, _T("%llu"), pt->second.parentCreateTime);
// 			//GetProcessPath(pt->first,m_Info.ProcessPath,true,NULL,m_Info.ProcessCTime);
// 			if (!_tcscmp(m_Info.ProcessPath, _T("null")))
// 			{
// 				//Sleep(100);
// 				//GetProcessOnlyPath(pInfo->pid,m_Info.ProcessPath);
// 				m_MemPro->SearchExecutePath(pt->first, m_Info.ProcessPath, pt->second.process_name);
// 			}
// 			SYSTEMTIME sys;
// 			GetLocalTime(&sys);
// 			swprintf_s(m_Info.ProcessTime, 20, _T("%4d/%02d/%02d %02d:%02d:%02d"), sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute, sys.wSecond);
// 			m_Info.ParentID = pt->second.parent_pid;
// 			if (pt->second.parentCreateTime > 0)
// 				m_MemPro->GetProcessPath(pt->second.parent_pid, m_Info.ParentPath, true, NULL, NULL);
// 			else
// 				_tcscpy_s(m_Info.ParentPath, MAX_PATH_EX, _T("null"));
// 			_tcscpy_s(m_Info.UnKnownHash, 50, _T("null"));
// 			m_Info.Injected = m_MemPro->CheckIsInjection(pt->first, pMembuf, m_Info.ProcessName, m_Info.UnKnownHash);
// 			//m_Info.Injected = FALSE;
// 			m_Info.StartRun = m_MemPro->CheckIsStartRun(&m_ServiceRun, &m_StartRun, pt->first/*,m_Info.HideService*/);

// 			m_MemPro->CheckIsInlineHook(pt->first, &m_Info.InlineHookInfo);

// 			TCHAR Md5Hashstr[50];
// 			memset(Md5Hashstr, '\0', 50);
// 			DWORD MD5ret = Md5Hash(m_Info.ProcessPath, Md5Hashstr);
// 			if (MD5ret == 0)
// 				lstrcpy(m_Info.ProcessHash, Md5Hashstr);
// 			else
// 				lstrcpy(m_Info.ProcessHash, _T("null"));

// 			if (_tcscmp(m_Info.ProcessPath, _T("null")))
// 			{
// 				DWORD AttRet = GetFileAttributes(m_Info.ProcessPath);
// 				if ((AttRet & FILE_ATTRIBUTE_HIDDEN) == FILE_ATTRIBUTE_HIDDEN)
// 					m_Info.HideAttribute = TRUE;
// 				DigitalSignatureInfo* DSinfo = new DigitalSignatureInfo;
// 				_tcscpy_s(DSinfo->SignerSubjectName, 256, _T("null"));
// 				bool DSret = GetDigitalSignature(m_Info.ProcessPath, DSinfo);
// 				if (DSret)
// 				{
// 					swprintf_s(m_Info.SignerSubjectName, 256, _T("%s"), DSinfo->SignerSubjectName);
// 				}
// 				else
// 				{
// 					lstrcpy(m_Info.SignerSubjectName, _T("null"));
// 				}
// 				delete DSinfo;
// 			}
// 			else
// 			{
// 				lstrcpy(m_Info.SignerSubjectName, _T("null"));
// 			}
// 			set<DWORD> ApiStringHash;
// 			m_MemPro->DumpExecute(pt->first, pt->second.process_name, pApiName, &ApiStringHash, m_Info.ProcessPath, &m_Info.Abnormal_dll);
// 			m_Info.InjectionOther = FALSE;
// 			m_Info.InjectionPE = FALSE;
// 			m_MemPro->CheckInjectionPtn(&ApiStringHash, m_Info.InjectionOther, m_Info.InjectionPE);
// 			ApiStringHash.clear();
// 			vector<TCPInformation>::iterator Tcpit;
// 			for (Tcpit = NetInfo.begin(); Tcpit != NetInfo.end(); Tcpit++)
// 			{
// 				if ((*Tcpit).ProcessID == pt->first)
// 				{
// 					WORD add1, add2, add3, add4;
// 					add1 = (WORD)((*Tcpit).LocalAddr & 255);
// 					add2 = (WORD)(((*Tcpit).LocalAddr >> 8) & 255);
// 					add3 = (WORD)(((*Tcpit).LocalAddr >> 16) & 255);
// 					add4 = (WORD)(((*Tcpit).LocalAddr >> 24) & 255);
// 					WORD add5, add6, add7, add8;
// 					add5 = (WORD)((*Tcpit).RemoteAddr & 255);
// 					add6 = (WORD)(((*Tcpit).RemoteAddr >> 8) & 255);
// 					add7 = (WORD)(((*Tcpit).RemoteAddr >> 16) & 255);
// 					add8 = (WORD)(((*Tcpit).RemoteAddr >> 24) & 255);
// 					char str[65536];
// 					sprintf_s(str, 65536, "%d.%d.%d.%d,%u,%d.%d.%d.%d,%u,%s>%lld", add1, add2, add3, add4, ntohs((u_short)(*Tcpit).LocalPort), add5, add6, add7, add8, ntohs((u_short)(*Tcpit).RemotePort), Convert2State((*Tcpit).State), NetworkClock);
// 					m_Info.NetString.insert(str);
// 				}
// 			}
// 			pInfo->insert(pair<DWORD, ProcessInfoData>(pt->first, m_Info));
// 		}
// 	}

// 	delete m_MemPro;
// 	delete m_AutoRun;
// 	m_StartRun.clear();
// 	m_ServiceRun.clear();
// 	NetInfo.clear();
// 	process_list.clear();
// }
// void Task::GiveScanDataSendServer(char* pMAC, char* pIP, char* pMode, map<DWORD, ProcessInfoData>* pFileInfo, vector<UnKnownDataInfo>* pUnKnownData, SOCKET* tcpSocket)
// {
// 	char* buff = new char[DATASTRINGMESSAGELEN];
// 	map<DWORD, ProcessInfoData>::iterator vit;
// 	int AllCount = (int)pFileInfo->size();
// 	int m_Count = 0;

// 	/*sprintf_s(buff, DATASTRINGMESSAGELEN, "%d", AllCount);
// 	int ret = GiveScanInfo(buff, tcpSocket);
// 	if (!ret) {
// 		printf("GiveScanInfo send failed\n");
// 		return;
// 	}*/
// 	int ret = 1;

// 	for (vit = pFileInfo->begin(); vit != pFileInfo->end(); vit++)
// 	{
// 		if (_tcscmp(vit->second.ProcessHash, _T("null")))
// 		{
// 			wchar_t* wTempStr = new wchar_t[DATASTRINGMESSAGELEN];

// 			// command line
// 			HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, vit->first);
// 			MemProcess* m_MemPro = new MemProcess;
// 			TCHAR* Comstr = new TCHAR[MAX_PATH_EX];
// 			DWORD ret1 = m_MemPro->GetRemoteCommandLineW(processHandle, Comstr, MAX_PATH_EX);
// 			if (ret1 == 0) _tcscpy_s(Comstr, MAX_PATH_EX, _T(""));
// 			CloseHandle(processHandle);

// 			// parent name, parent path
// 			TCHAR* ParentName = new TCHAR[MAX_PATH];
// 			TCHAR* ParentPath = new TCHAR[MAX_PATH];
// 			_tcscpy_s(ParentName, 259, _T("null"));
// 			_tcscpy_s(ParentPath, 259, _T("null"));
// 			auto it = pFileInfo->find(vit->second.ParentID);
// 			if (it != pFileInfo->end()) {
// 				_tcscpy_s(ParentName, MAX_PATH, it->second.ProcessName);
// 				_tcscpy_s(ParentPath, MAX_PATH, it->second.ProcessPath);
// 			}

// 			int Service = 0, AutoRun = 0;
// 			if (vit->second.StartRun == 1) Service = 1;
// 			else if (vit->second.StartRun == 2) AutoRun = 1;
// 			else if (vit->second.StartRun == 3) {
// 				Service = 1;
// 				AutoRun = 1;
// 			}

// 			swprintf_s(wTempStr, DATASTRINGMESSAGELEN, L"%s|%s|%s|%s|%s|%ld|%s|%s|%s|%ld|%d,%d|%d|%d,%d|%d,%d"
// 				, vit->second.ProcessName, vit->second.ProcessCTime, Comstr, vit->second.ProcessHash, vit->second.ProcessPath,
// 				vit->second.ParentID, ParentName, ParentPath, vit->second.SignerSubjectName, vit->first, vit->second.InjectionPE, vit->second.InjectionOther
// 				, vit->second.Injected, Service, AutoRun, vit->second.HideProcess, vit->second.HideAttribute
// 			);

// 			// abnormal dll
// 			char* cTempStr = CStringToCharArray(wTempStr, CP_UTF8);
// 			strcpy_s(buff, DATASTRINGMESSAGELEN, cTempStr);
// 			if (!vit->second.Abnormal_dll.empty())
// 			{
// 				strcat_s(buff, DATASTRINGMESSAGELEN, "|");
// 				set<string>::iterator dllit;
// 				for (dllit = vit->second.Abnormal_dll.begin(); dllit != vit->second.Abnormal_dll.end(); dllit++)
// 				{
// 					char* dllstr = new char[4096];
// 					sprintf_s(dllstr, 4096, "%s;", (*dllit).c_str());
// 					if ((strlen(dllstr) + strlen(buff)) >= DATASTRINGMESSAGELEN)
// 					{
// 						ret = GiveScanFragment(buff, tcpSocket);
// 						memset(buff, '\0', DATASTRINGMESSAGELEN);
// 						if (ret <= 0)
// 						{
// 							delete[] dllstr;
// 							break;
// 						}
// 					}
// 					strcat_s(buff, DATASTRINGMESSAGELEN, dllstr);
// 					delete[] dllstr;
// 				}
// 				if (ret <= 0)
// 					break;
// 			}
// 			else
// 				strcat_s(buff, DATASTRINGMESSAGELEN, "|null");


// 			// inline hook
// 			if (!vit->second.InlineHookInfo.empty())
// 			{
// 				strcat_s(buff, DATASTRINGMESSAGELEN, "|");
// 				set<string>::iterator Inlineit;
// 				for (Inlineit = vit->second.InlineHookInfo.begin(); Inlineit != vit->second.InlineHookInfo.end(); Inlineit++)
// 				{
// 					char* Inlinestr = new char[4096];
// 					sprintf_s(Inlinestr, 4096, "%s;", (*Inlineit).c_str());
// 					if ((strlen(Inlinestr) + strlen(buff)) >= DATASTRINGMESSAGELEN)
// 					{

// 						ret = GiveScanFragment(buff, tcpSocket);
// 						memset(buff, '\0', DATASTRINGMESSAGELEN);
// 						if (ret <= 0)
// 						{
// 							delete[] Inlinestr;
// 							break;
// 						}
// 					}
// 					strcat_s(buff, DATASTRINGMESSAGELEN, Inlinestr);
// 					delete[] Inlinestr;
// 				}
// 				if (ret <= 0)
// 					break;
// 			}
// 			else
// 				strcat_s(buff, DATASTRINGMESSAGELEN, "|null");

// 			// Network
// 			if (!vit->second.NetString.empty())
// 			{
// 				strcat_s(buff, DATASTRINGMESSAGELEN, "|");
// 				set<string>::iterator netit;
// 				for (netit = vit->second.NetString.begin(); netit != vit->second.NetString.end(); netit++)
// 				{
// 					char* netstr = new char[4096];
// 					sprintf_s(netstr, 4096, "%s;", (*netit).c_str());
// 					if ((strlen(netstr) + strlen(buff)) >= DATASTRINGMESSAGELEN)
// 					{
// 						ret = GiveScanFragment(buff, tcpSocket);
// 						memset(buff, '\0', DATASTRINGMESSAGELEN);
// 						if (ret <= 0)
// 						{
// 							delete[] netstr;
// 							break;
// 						}
// 					}
// 					strcat_s(buff, DATASTRINGMESSAGELEN, netstr);
// 					delete[] netstr;
// 				}
// 				if (ret <= 0)
// 					break;
// 			}
// 			else
// 				strcat_s(buff, DATASTRINGMESSAGELEN, "|null");


// 			delete[] ParentName;
// 			delete[] ParentPath;
// 			delete[] Comstr;
// 			delete[] cTempStr;


// 			ret = GiveScan(buff, tcpSocket);
// 			if (ret <= 0) {
// 				printf("Give Scan Send Failed\n");
// 				break;
// 			}
// 			else memset(buff, '\0', DATASTRINGMESSAGELEN);

// 			//break;
// 		}
// 		m_Count++;
// 	}

// 	//m_Hash.clear();

// 	//if (!pUnKnownData->empty())
// 	//{
// 	//	printf("pUnKnownData\n");
// 	//	vector<UnKnownDataInfo>::iterator ut;
// 	//	memset(TempStr, '\0', DATASTRINGMESSAGELEN);
// 	//	wchar_t* wUnKownInfoStr = new wchar_t[DATASTRINGMESSAGELEN];
// 	//	int ret = 1;
// 	//	char* cUnKownInfoStr = NULL;
// 	//	for (ut = pUnKnownData->begin(); ut != pUnKnownData->end(); ut++)
// 	//	{
// 	//		swprintf_s(wUnKownInfoStr, DATASTRINGMESSAGELEN, L"%lu|%s|%d", (*ut).Pid, (*ut).ProcessName, (*ut).SizeInfo);
// 	//		cUnKownInfoStr = CStringToCharArray(wUnKownInfoStr, CP_UTF8);
// 	//		sprintf_s(TempStr, DATASTRINGMESSAGELEN, "%s", cUnKownInfoStr);
// 	//		ret = socketsend->SendMessageToServer(functionName_GiveProcessUnknownInfo, TempStr);
// 	//		if (ret <= 0)
// 	//			break;
// 	//		memset(TempStr, '\0', DATASTRINGMESSAGELEN);
// 	//		if ((*ut).SizeInfo > DATASTRINGMESSAGELEN /*&& ret != -3*/)
// 	//		{
// 	//			int tmplen = (*ut).SizeInfo;
// 	//			for (DWORD i = 0; i < (*ut).SizeInfo; i += DATASTRINGMESSAGELEN)
// 	//			{
// 	//				char* TmpBuffer = new char[DATASTRINGMESSAGELEN];
// 	//				memset(TmpBuffer, '\x00', DATASTRINGMESSAGELEN);
// 	//				if (tmplen < DATASTRINGMESSAGELEN)
// 	//					memcpy(TmpBuffer, (*ut).Data + i, tmplen);
// 	//				else
// 	//				{
// 	//					memcpy(TmpBuffer, (*ut).Data + i, DATASTRINGMESSAGELEN);
// 	//					tmplen -= DATASTRINGMESSAGELEN;
// 	//				}
// 	//				ret = socketsend->SendMessageToServer(functionName_GiveProcessUnknownInfo, TmpBuffer);
// 	//				//Sendret = m_Client->SendDataBufToServer(pInfo->MAC,pInfo->IP,WorkStr,TmpBuffer);
// 	//				delete[] TmpBuffer;
// 	//				if (ret <= 0)
// 	//				{
// 	//					break;
// 	//				}
// 	//			}
// 	//			if (ret <= 0)
// 	//				break;
// 	//		}
// 	//		else
// 	//		{
// 	//			char* TmpBuffer = new char[DATASTRINGMESSAGELEN];
// 	//			memset(TmpBuffer, '\x00', DATASTRINGMESSAGELEN);
// 	//			memcpy(TmpBuffer, (*ut).Data, (*ut).SizeInfo);
// 	//			ret = socketsend->SendMessageToServer(functionName_GiveProcessUnknownInfo, TmpBuffer);
// 	//			//Sendret = m_Client->SendDataBufToServer(pInfo->MAC,pInfo->IP,WorkStr,TmpBuffer);
// 	//			delete[] TmpBuffer;
// 	//			if (ret <= 0)
// 	//				break;
// 	//		}
// 	//		
// 	//		ret = socketsend->SendMessageToServer(functionName_GiveProcessUnknownEnd, null);
// 	//		if (ret <= 0)
// 	//			break;
// 	//		delete[] cUnKownInfoStr;
// 	//		cUnKownInfoStr = NULL;
// 	//	}
// 	//	if (cUnKownInfoStr != NULL)
// 	//		delete[] cUnKownInfoStr;
// 	//	delete[] wUnKownInfoStr;
// 	//	for (ut = pUnKnownData->begin(); ut != pUnKnownData->end(); ut++)
// 	//	{
// 	//		delete[](*ut).Data;
// 	//	}
// 	//}

// 	delete[] buff;
// 	ret = GiveScanEnd(pMode, tcpSocket);
// }

// int Task::GiveScanInfo(char* buff, SOCKET* tcpSocket) {
// 	char* functionName = new char[24];
// 	strcpy_s(functionName, 24, "GiveScanInfo");
// 	return socketsend->SendDataToServer(functionName, buff, tcpSocket);
// }
// int Task::GiveScan(char* buff, SOCKET* tcpSocket) {
// 	char* functionName = new char[24];
// 	strcpy_s(functionName, 24, "GiveScan");
// 	printf("%s\n", buff);
// 	return socketsend->SendDataToServer(functionName, buff, tcpSocket);
// }
// int Task::GiveScanFragment(char* buff, SOCKET* tcpSocket) {
// 	char* functionName = new char[24];
// 	strcpy_s(functionName, 24, "GiveScanFragment");
// 	printf("%s\n", buff);
// 	return socketsend->SendDataToServer(functionName, buff, tcpSocket);
// }
// int Task::GiveScanEnd(char* buff, SOCKET* tcpSocket) {
// 	char* functionName = new char[24];
// 	strcpy_s(functionName, 24, "GiveScanEnd");
// 	return socketsend->SendDataToServer(functionName, buff, tcpSocket);
// }
// int Task::GiveScanProgress(char* buff, SOCKET* tcpSocket) {
// 	char* functionName = new char[24];
// 	strcpy_s(functionName, 24, "GiveScanProgress");
// 	int ret = socketsend->SendDataToServer(functionName, buff, tcpSocket);
// 	if (ret <= 0) { 
// 		log.logger("Error", "GiveScanProgress Error"); 
// 		std::exit(0);
// 	}
// 	else {
// 		return ret;
// 	}
// }


// // Explorer
// int Task::GetDrive(StrPacket* udata) { return GiveDriveInfo(); }
// int Task::GiveDriveInfo() { 
// 	char* m_DriveInfo = GetMyPCDrive();
// 	char* functionName = new char[24];
// 	strcpy_s(functionName, 24, "GiveDriveInfo");
// 	int ret = socketsend->SendMessageToServer(functionName, m_DriveInfo);
// 	return ret;
// }
// char* Task::GetMyPCDrive()
// {
// 	char* driveStr = new char[STRINGMESSAGELEN];
// 	driveStr[0] = '\0';
// 	for (int i = 2; i < 26; i++)
// 	{
// 		char* drive = new char[10];
// 		strcpy_s(drive, 10, GetDriveStr(i));
// 		UINT type = GetDriveTypeA(drive);
// 		if (!(type == DRIVE_FIXED || type == DRIVE_REMOVABLE))
// 		{
// 			delete[] drive;
// 			continue;
// 		}
// 		char* volname = new char[_MAX_FNAME];
// 		char* filesys = new char[_MAX_FNAME];
// 		DWORD VolumeSerialNumber, MaximumComponentLength, FileSystemFlags;
// 		if (GetVolumeInformationA(drive, volname, _MAX_FNAME, &VolumeSerialNumber, &MaximumComponentLength, &FileSystemFlags, filesys, _MAX_FNAME))
// 		{
// 			//drive.Remove(L'\\');
// 			for (int j = (int)strlen(drive) - 1; j >= 0; j--)
// 			{
// 				if (drive[j] == ':')
// 				{
// 					drive[j] = '\x0';
// 					break;
// 				}
// 			}
// 			if (type == DRIVE_FIXED)
// 			{
// 				strcat_s(driveStr, STRINGMESSAGELEN, drive);
// 				strcat_s(driveStr, STRINGMESSAGELEN, "-");
// 				strcat_s(driveStr, STRINGMESSAGELEN, filesys);
// 				strcat_s(driveStr, STRINGMESSAGELEN, ",HDD");
// 				strcat_s(driveStr, STRINGMESSAGELEN, "|");
// 			}
// 			else if (type == DRIVE_REMOVABLE)
// 			{
// 				strcat_s(driveStr, STRINGMESSAGELEN, drive);
// 				strcat_s(driveStr, STRINGMESSAGELEN, "-");
// 				strcat_s(driveStr, STRINGMESSAGELEN, filesys);
// 				strcat_s(driveStr, STRINGMESSAGELEN, ",USB");
// 				strcat_s(driveStr, STRINGMESSAGELEN, "|");
// 			}
// 		}
// 		delete[] filesys;
// 		delete[] volname;
// 		delete[] drive;
// 	}
// 	return driveStr;
// }

// int Task::ExplorerInfo_(StrPacket* udata) {

// 	char delimiter = '|';
// 	char Drive[2]; 
// 	char FileSystem[20];

// 	char* context; 

// 	char* token = strtok_s(udata->csMsg, &delimiter, &context);
// 	if (token != nullptr) {
// 		strncpy_s(Drive, sizeof(Drive), token, sizeof(Drive) - 1);
// 		Drive[sizeof(Drive) - 1] = '\0';

// 		token = strtok_s(nullptr, &delimiter, &context);
// 		if (token != nullptr) {
// 			strncpy_s(FileSystem, sizeof(FileSystem), token, sizeof(FileSystem) - 1);
// 			FileSystem[sizeof(FileSystem) - 1] = '\0';
// 		}
// 	}

// 	DWORD ExplorerProcessPid = 0;
// 	TCHAR* RunExeStr = new TCHAR[MAX_PATH];
// 	TCHAR* RunComStr = new TCHAR[512];
// 	GetModuleFileName(GetModuleHandle(NULL), RunExeStr, MAX_PATH);

// 	//TCHAR MyName[MAX_PATH];
// 	//swprintf_s(MyName, MAX_PATH, L"%hs", "./Agent_VS2019");
// 	wstring filename = tool.GetFileName();
// 	TCHAR MyName[MAX_PATH];
// 	wcscpy_s(MyName, filename.c_str());
// 	TCHAR ServerIP[MAX_PATH];
// 	swprintf_s(ServerIP, MAX_PATH, L"%hs", info->ServerIP);
// 	TCHAR Drive_[MAX_PATH];
// 	swprintf_s(Drive_, MAX_PATH, L"%hs", Drive);
// 	TCHAR FileSystem_[MAX_PATH];
// 	swprintf_s(FileSystem_, MAX_PATH, L"%hs", FileSystem);

// 	swprintf_s(RunComStr, 512, L"\"%s\" %s %d Explorer %s %s", MyName, ServerIP, info->Port, Drive_, FileSystem_);
// 	wprintf(L"Run Process: %ls\n", RunComStr);
// 	RunProcessEx(RunExeStr, RunComStr, 1024, FALSE, FALSE, ExplorerProcessPid);

// 	info->processMap["Explorer"] = ExplorerProcessPid;
// 	log.logger("Debug", "Explorer enabled");

// 	return 1;
// }
// int Task::GiveExplorerData(char* Drive, char* FileSystem) {


// 	//SOCKET* tcpSocket = CreateNewSocket();
// 	//if (tcpSocket == nullptr) return 0;
// 	int ret = 0;

// 	ExplorerInfo* m_Info = new ExplorerInfo;
// 	wchar_t DriveName[20];
// 	size_t convertedChars = 0;
// 	mbstowcs_s(&convertedChars, DriveName, sizeof(DriveName) / sizeof(wchar_t), Drive, sizeof(Drive) - 1);
// 	CFileSystem* pfat = new CFileSystem(DriveName);
// 	m_Info->Drive = static_cast<wchar_t>(Drive[0]);
// 	mbstowcs_s(&convertedChars, m_Info->DriveInfo, sizeof(m_Info->DriveInfo) / sizeof(wchar_t), FileSystem, sizeof(FileSystem) - 1);


// 	wchar_t* drive = new wchar_t[5];
// 	swprintf_s(drive, 5, L"%c:\\", m_Info->Drive);
// 	wchar_t* volname = new wchar_t[_MAX_FNAME];
// 	wchar_t* filesys = new wchar_t[_MAX_FNAME];
// 	DWORD VolumeSerialNumber, MaximumComponentLength, FileSystemFlags;
// 	if (GetVolumeInformation(drive, volname, _MAX_FNAME, &VolumeSerialNumber, &MaximumComponentLength, &FileSystemFlags, filesys, _MAX_FNAME))
// 	{
// 		if ((wcsstr(m_Info->DriveInfo, filesys) != 0))
// 		{
// 			if (!wcscmp(filesys, L"NTFS"))
// 			{
// 				NTFSSearchCore* searchCore = new NTFSSearchCore;
// 				try {
// 					printf("NTFS start...\n");
// 					ret = NTFSSearch(m_Info->Drive, info->MAC, info->IP, info->tcpSocket, Drive, FileSystem);
// 				}
// 				catch (...) {
// 					ret = 1;
// 				}
// 				if (ret == 0) {
// 					char* null = new char[5];
// 					strcpy_s(null, 5, "null");
// 					ret = GiveExplorerEnd(null, info->tcpSocket);
// 					delete[] null;
// 				}
// 				else {
// 					char* msg = new char[22];
// 					strcpy_s(msg, 22, "ErrorLoadingMFTTable");
// 					ret = GiveExplorerError(msg, info->tcpSocket);
// 					delete[] msg;
// 				}

// 				delete searchCore;
// 			}
// 			else if (!wcscmp(filesys, L"FAT32"))
// 			{
// 				//int ret1 = 1;
// 				//char* TempStr = new char[DATASTRINGMESSAGELEN];
// 				//memset(TempStr, '\0', DATASTRINGMESSAGELEN);
// 				//char* m_DataStr = new char[1000];
// 				//sprintf_s(m_DataStr, 1000, "5|.|5|0|2|1970/01/01 08:00:00|1970/01/01 08:00:00|1970/01/01 08:00:00|null,null,null|0|1\n");
// 				//strcat_s(TempStr, DATASTRINGMESSAGELEN, m_DataStr);
// 				//vector<DeleteFATFileInfo> FATDeleteFile;
// 				//DWORD LastCluster = 0;
// 				//unsigned int Count = 1;
// 				//unsigned int ProgressCount = 1;
// 				//clock_t start;
// 				//start = clock();
// 				//bool ret = pfat->initFDT(this, info->MAC, info->IP, TempStr, ProgressCount, Count, LastCluster, &FATDeleteFile, start);
// 				//if (ret)
// 				//{
// 				//	if (!FATDeleteFile.empty())
// 				//	{
// 				//		vector<DeleteFATFileInfo>::iterator it;
// 				//		for (it = FATDeleteFile.begin(); it != FATDeleteFile.end(); it++)
// 				//		{
// 				//			LastCluster++;
// 				//			if (LastCluster == 5)
// 				//				LastCluster++;
// 				//			wchar_t* wstr = new wchar_t[1024];
// 				//			DWORD FirstClister = (*it).FirstDataCluster + 5;
// 				//			if ((*it).isDirectory == 0)
// 				//			{
// 				//				TCHAR* m_MD5Str = new TCHAR[50];
// 				//				memset(m_MD5Str, '\0', 50);
// 				//				TCHAR* Signaturestr = new TCHAR[20];
// 				//				memset(Signaturestr, '\0', 20);
// 				//				//DWORD FirstCluster = newEntry->GetTheFirstDataCluster()+5;
// 				//				if (pfat->FileHashAndSignature((*it).FirstDataCluster, (*it).FileSize, (*it).FileName, m_MD5Str, Signaturestr))
// 				//				{
// 				//					swprintf_s(wstr, 1024, L"%lu|%s|%lu|1|%d|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%s,%s,%lu|%lu|1\n",
// 				//						LastCluster, (*it).FileName, (*it).ParentFirstDataCluster, (*it).isDirectory
// 				//						, (*it).CT.wYear, (*it).CT.wMonth, (*it).CT.wDay, (*it).CT.wHour, (*it).CT.wMinute, (*it).CT.wSecond,
// 				//						(*it).WT.wYear, (*it).WT.wMonth, (*it).WT.wDay, (*it).WT.wHour, (*it).WT.wMinute, (*it).WT.wSecond,
// 				//						(*it).AT.wYear, (*it).AT.wMonth, (*it).AT.wDay, (*it).AT.wHour, (*it).AT.wMinute, (*it).AT.wSecond, m_MD5Str, Signaturestr, FirstClister, (*it).FileSize);
// 				//				}
// 				//				else
// 				//				{
// 				//					swprintf_s(wstr, 1024, L"%lu|%s|%lu|1|%d|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|null,null,%lu|%lu|1\n",
// 				//						LastCluster, (*it).FileName, (*it).ParentFirstDataCluster, (*it).isDirectory
// 				//						, (*it).CT.wYear, (*it).CT.wMonth, (*it).CT.wDay, (*it).CT.wHour, (*it).CT.wMinute, (*it).CT.wSecond,
// 				//						(*it).WT.wYear, (*it).WT.wMonth, (*it).WT.wDay, (*it).WT.wHour, (*it).WT.wMinute, (*it).WT.wSecond,
// 				//						(*it).AT.wYear, (*it).AT.wMonth, (*it).AT.wDay, (*it).AT.wHour, (*it).AT.wMinute, (*it).AT.wSecond, FirstClister, (*it).FileSize);
// 				//				}
// 				//				delete[] Signaturestr;
// 				//				delete[] m_MD5Str;
// 				//			}
// 				//			else
// 				//			{
// 				//				swprintf_s(wstr, 1024, L"%lu|%s|%lu|1|%d|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|%02hu/%02hu/%02hu %02hu:%02hu:%02hu|null,null,%lu|%lu|1\n",
// 				//					LastCluster, (*it).FileName, (*it).ParentFirstDataCluster, (*it).isDirectory
// 				//					, (*it).CT.wYear, (*it).CT.wMonth, (*it).CT.wDay, (*it).CT.wHour, (*it).CT.wMinute, (*it).CT.wSecond,
// 				//					(*it).WT.wYear, (*it).WT.wMonth, (*it).WT.wDay, (*it).WT.wHour, (*it).WT.wMinute, (*it).WT.wSecond,
// 				//					(*it).AT.wYear, (*it).AT.wMonth, (*it).AT.wDay, (*it).AT.wHour, (*it).AT.wMinute, (*it).AT.wSecond, FirstClister, (*it).FileSize);
// 				//			}
// 				//			char* m_DataStr = CStringToCharArray(wstr, CP_UTF8);
// 				//			strcat_s(TempStr, DATASTRINGMESSAGELEN, m_DataStr);
// 				//			ProgressCount++;
// 				//			Count++;
// 				//			clock_t endTime = clock();
// 				//			if ((endTime - start) > 300000)
// 				//			{
// 				//				char* ProgressStr = new char[10];
// 				//				sprintf_s(ProgressStr, 10, "%u", ProgressCount);
// 				//				strcat_s(TempStr, DATASTRINGMESSAGELEN, ProgressStr);
// 				//				ret1 = socketsend->SendDataToServer(functionName_GiveExplorerData, TempStr, info->tcpSocket);
// 				//				if (ret1 <= 0)
// 				//				{
// 				//					delete[] ProgressStr;
// 				//					delete[] m_DataStr;
// 				//					delete[] wstr;
// 				//					break;
// 				//				}
// 				//				start = clock();
// 				//				Count = 0;
// 				//				memset(TempStr, '\0', DATASTRINGMESSAGELEN);
// 				//				delete[] ProgressStr;
// 				//			}
// 				//			else
// 				//			{
// 				//				if ((Count % 60) == 0 && Count >= 60)
// 				//				{
// 				//					char* ProgressStr = new char[10];
// 				//					sprintf_s(ProgressStr, 10, "%u", ProgressCount);
// 				//					strcat_s(TempStr, DATASTRINGMESSAGELEN, ProgressStr);
// 				//					ret1 = socketsend->SendDataToServer(functionName_GiveExplorerData, TempStr, info->tcpSocket);
// 				//					if (ret1 <= 0)
// 				//					{
// 				//						delete[] ProgressStr;
// 				//						delete[] m_DataStr;
// 				//						delete[] wstr;
// 				//						break;
// 				//					}
// 				//					start = clock();
// 				//					Count = 0;
// 				//					memset(TempStr, '\0', DATASTRINGMESSAGELEN);
// 				//					delete[] ProgressStr;
// 				//				}
// 				//			}
// 				//			delete[] m_DataStr;
// 				//			delete[] wstr;
// 				//		}
// 				//	}
// 				//	if (ret1 > 0)
// 				//	{
// 				//		if (TempStr[0] != '\0')
// 				//		{
// 				//			char* ProgressStr = new char[10];
// 				//			sprintf_s(ProgressStr, 10, "%u", ProgressCount);
// 				//			strcat_s(TempStr, DATASTRINGMESSAGELEN, ProgressStr);
// 				//			ret1 = socketsend->SendDataToServer(functionName_GiveExplorerData, TempStr, info->tcpSocket);
// 				//			delete[] ProgressStr;
// 				//		}
// 				//	}
// 				//	if (ret1 > 0)
// 				//		int	ret = socketsend->SendMessageToServer(functionName_GiveExplorerEnd, null);
// 				//}
// 				//else
// 				//	ret = socketsend->SendMessageToServer(functionName_GiveExplorerError, ErrorLoadingFATTable);
// 				//FATDeleteFile.clear();
// 				//delete[] m_DataStr;
// 				//delete[] TempStr;
// 			}
// 			else
// 			{
// 				//char* TempStr = new char[DATASTRINGMESSAGELEN];
// 				//memset(TempStr, '\0', DATASTRINGMESSAGELEN);
// 				//char* m_DataStr = new char[1000];
// 				//sprintf_s(m_DataStr, 1000, "5|.|5|0|2|1970/01/01 08:00:00|1970/01/01 08:00:00|1970/01/01 08:00:00|null|0|9\n");
// 				//strcat_s(TempStr, DATASTRINGMESSAGELEN, m_DataStr);
// 				////wchar_t * DriveStr = CharArrayToWString(drive,CP_UTF8);
// 				//unsigned int ProgressCount = 1;
// 				//unsigned int Index = 5;
// 				//unsigned int Count = 1;
// 				//int ret = 1;
// 				//SysExplorerSearch(drive, 5, Index, TempStr, ProgressCount, Count);
// 				//if (TempStr[0] != '\0')
// 				//{
// 				//	char* ProgressStr = new char[10];
// 				//	sprintf_s(ProgressStr, 10, "%u", ProgressCount);
// 				//	strcat_s(TempStr, DATASTRINGMESSAGELEN, ProgressStr);
// 				//	ret = socketsend->SendDataToServer(functionName_GiveExplorerData, TempStr);
// 				//	delete[] ProgressStr;
// 				//}
// 				////if(Client_Socket->IsOpened())
// 				//if (ret > 0)
// 				//	int	ret = socketsend->SendMessageToServer(functionName_GiveExplorerEnd, null);
// 				//delete[] m_DataStr;
// 				//delete[] TempStr;
// 			}
// 		}
// 		else
// 		{
// 			char* msg = new char[22];
// 			strcpy_s(msg, 22, "ErrorNotFormat");
// 			ret = GiveExplorerError(msg, info->tcpSocket);
// 			delete[] msg;

// 		}
// 	}
// 	else
// 	{
// 		char* msg = new char[22];
// 		strcpy_s(msg, 22, "ErrorNoDrive");
// 		ret = GiveExplorerError(msg, info->tcpSocket);
// 		delete[] msg;
// 	}

// 	delete[] filesys;
// 	delete[] volname;
// 	delete[] drive;
// 	delete m_Info;

// 	//delete[] wMgs;
// 	//closesocket(*tcpSocket);
// 	return ret;

// }
// int Task::NTFSSearch(wchar_t vol_name, char* pMAC, char* pIP, SOCKET* tcpSocket, char* Drive, char* FileSystem) {
	
// 	CNTFSVolume* m_curSelectedVol = new CNTFSVolume(vol_name);
// 	if (m_curSelectedVol == NULL) {
// 		printf("Error when getVolumeByName\n");
// 		delete m_curSelectedVol;
// 		return 1;
// 	}

// 	if (!m_curSelectedVol->IsVolumeOK()) {
// 		printf("Not a valid NTFS volume or NTFS version < 3.0\n");
// 		delete m_curSelectedVol;
// 		return 1;
// 	}

// 	unsigned int m_progressIdx;
// 	unsigned int m_Count = 0;
// 	char* TempStr = new char[DATASTRINGMESSAGELEN];
// 	memset(TempStr, '\0', DATASTRINGMESSAGELEN);

// 	// Give Drive Info to Server
// 	char* RecordCount = new char[DATASTRINGMESSAGELEN];
// 	sprintf_s(RecordCount, DATASTRINGMESSAGELEN, "%s|%s", Drive, FileSystem);
// 	int	ret = Explorer(RecordCount ,tcpSocket);

// 	TCHAR* Explorer_txt = new TCHAR[MAX_PATH_EX];
// 	GetMyPath(Explorer_txt);
// 	_tcscat_s(Explorer_txt, MAX_PATH_EX, _T("\\Explorer.txt"));
// 	DeleteFile(Explorer_txt);
// 	TCHAR* Explorer_zip = new TCHAR[MAX_PATH_EX];
// 	GetMyPath(Explorer_zip);
// 	_tcscat_s(Explorer_zip, MAX_PATH_EX, _T("\\Explorer.zip"));
// 	DeleteFile(Explorer_zip);

// 	//std::remove("Explorer.txt");
// 	//std::remove("Explorer.zip");	

// 	std::wofstream outFile(Explorer_txt, std::ios::app);
// 	if (!outFile.is_open()) {
// 		log.logger("Error", "Explorer.txt open failed");
// 	}

// 	// collect Explorer
// 	printf("Collecting Explorer...\n");
// 	for (m_progressIdx = MFT_IDX_MFT; m_progressIdx < m_curSelectedVol->GetRecordsCount(); m_progressIdx++) {
// 	//for (m_progressIdx = MFT_IDX_MFT; m_progressIdx < 30000; m_progressIdx++) {
// 		if (m_progressIdx % 10000 == 0) {
// 			printf("%d\n", m_progressIdx);
// 			char* Progress = new char[DATASTRINGMESSAGELEN];
// 			sprintf_s(Progress, DATASTRINGMESSAGELEN, "%u/%d", m_progressIdx, m_curSelectedVol->GetRecordsCount());
// 			GiveExplorerProgress(Progress, tcpSocket);
// 			delete[] Progress;
// 		}

// 		CFileRecord* fr = new CFileRecord(m_curSelectedVol);
// 		if (fr == NULL) {
// 			printf("CFileRecord is null\n");
// 			continue;	// skip to next
// 		}

// 		// Only parse Standard Information and File Name attributes
// 		fr->SetAttrMask(MASK_FILE_NAME | MASK_DATA);	// StdInfo will always be parsed
// 		if (!fr->ParseFileRecord(m_progressIdx))
// 		{
// 			delete fr;
// 			continue;	// skip to next
// 		}

// 		if (!fr->ParseFileAttrs())
// 		{
// 			delete fr;
// 			continue;	// skip to next
// 		}

// 		TCHAR fn[MAX_PATH];
// 		if (fr->GetFileName(fn, MAX_PATH) <= 0)
// 		{
// 			delete fr;
// 			continue;	// skip to next
// 		}

// 		ULONGLONG datalen = 0;

// 		if (!fr->IsDirectory())
// 		{
// 			const CAttrBase* data = fr->FindStream();
// 			if (data)
// 			{
// 				datalen = data->GetDataSize();
// 				if (fr->IsCompressed() && datalen == 0)
// 					datalen = fr->GetFileSize();
// 			}
// 			else
// 			{
// 				if (fr->IsCompressed() && datalen == 0)
// 					datalen = fr->GetFileSize();
// 			}
// 		}
// 		ULONGLONG ParentId = 0;
// 		ParentId = fr->GetParentRef();
// 		if (ParentId == 0)
// 			ParentId = 5;
// 		else
// 			ParentId = ParentId & 0x0000FFFFFFFFFFFF;

// 		FILETIME	FileCreateTime;		// File creation time
// 		FILETIME	FileWriteTime;		// File altered time
// 		FILETIME	FileAccessTime;		// File read time
// 		FILETIME	EntryModifiedTime;
// 		fr->GetFileCreateTime(&FileCreateTime);
// 		fr->GetFileWriteTime(&FileWriteTime);
// 		fr->GetFileAccessTime(&FileAccessTime);
// 		fr->GetEntryModifiedTime(&EntryModifiedTime);

// 		time_t createTimeUnix = tool.FileTimeToUnixTime(FileCreateTime);
// 		time_t writeTimeUnix = tool.FileTimeToUnixTime(FileWriteTime);
// 		time_t accessTimeUnix = tool.FileTimeToUnixTime(FileAccessTime);
// 		time_t modifiedTimeUnix = tool.FileTimeToUnixTime(EntryModifiedTime);

// 		wchar_t CreateTimeWstr[50];
// 		wchar_t WriteTimeWstr[50];
// 		wchar_t AccessTimeWstr[50];
// 		wchar_t EntryModifiedTimeWstr[50];
// 		swprintf_s(CreateTimeWstr, 50, L"%lld", static_cast<long long>(createTimeUnix));
// 		swprintf_s(WriteTimeWstr, 50, L"%lld", static_cast<long long>(writeTimeUnix));
// 		swprintf_s(AccessTimeWstr, 50, L"%lld", static_cast<long long>(accessTimeUnix));
// 		if (EntryModifiedTime.dwLowDateTime != 0) swprintf_s(EntryModifiedTimeWstr, 50, L"%lld", static_cast<long long>(modifiedTimeUnix));
// 		else swprintf_s(EntryModifiedTimeWstr, 50, L"1");

// 		wchar_t* wstr = new wchar_t[1024];
// 		swprintf_s(wstr, 1024, L"%s|%d|%d|%s|%s|%s|%s|%llu|%u|%llu\n", fn, fr->IsDeleted(), fr->IsDirectory(), CreateTimeWstr, WriteTimeWstr, AccessTimeWstr, EntryModifiedTimeWstr, datalen, m_progressIdx, ParentId);
		
// 		// write to Explorer.txt
// 		char* m_DataStr = CStringToCharArray(wstr, CP_UTF8);
// 		strcat_s(TempStr, DATASTRINGMESSAGELEN, m_DataStr);
// 		delete[] wstr;
// 		if ((m_Count % 60) == 0 && m_Count >= 60) {
// 			if (outFile.good()) outFile << TempStr;
// 			else {
// 				log.logger("Error", "write to txt failed");
// 			}
// 			memset(TempStr, '\0', DATASTRINGMESSAGELEN);
// 		}

// 		m_Count++;
// 		delete fr;
// 	}
// 	outFile.close();
	

// 	//const TCHAR* zipFileName = Explorer_zip;
// 	//const TCHAR* sourceFilePath = Explorer_txt; // _T("Explorer.txt")
	
// 	// Compress Explorer.txt
// 	if (tool.CompressFileToZip(Explorer_zip, Explorer_txt)) _tprintf(_T("File compressed and added to ZIP successfully.\n"));
// 	else log.logger("Error", "failed to add file to Zip");

// 	// Get Explorer.txt Size
// 	std::ifstream file(Explorer_zip, std::ios::binary);
// 	if (!file.is_open()) {
// 		std::cout << "Failed to open file." << std::endl;
// 		log.logger("Error", "failed to open zip file");
// 		return 0;
// 	}
// 	file.seekg(0, std::ios::end);
// 	std::streampos fileSize = file.tellg();
// 	file.close();
// 	long long fileSizeLL = static_cast<long long>(fileSize);

// 	// send GiveExplorerInfo
// 	char* FileSize = new char[DATASTRINGMESSAGELEN];
// 	sprintf_s(FileSize, DATASTRINGMESSAGELEN, "%lld", fileSizeLL);
// 	ret = GiveExplorerInfo(FileSize, tcpSocket);
// 	delete[] FileSize;
	
// 	// send zip file
// 	SendZipFileToServer(Explorer_zip, tcpSocket);

// 	DeleteFile(Explorer_txt);
// 	DeleteFile(Explorer_zip);

// 	//if (std::remove("Explorer.txt") != 0) perror("Error delete Explorer.txt\n");
// 	//if (std::remove("Explorer.zip") != 0) perror("Error delete Explorer.zip\n");


// 	delete[] TempStr;
// 	delete m_curSelectedVol;

// 	return 0;
// }
// void Task::SendZipFileToServer(const TCHAR* zipFileName, SOCKET* tcpSocket)
// {

// 	HANDLE m_File = CreateFile(zipFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
// 	if (m_File != INVALID_HANDLE_VALUE)
// 	{
// 		DWORD m_Filesize = GetFileSize(m_File, NULL);
// 		int Sendret;
// 		char* InfoStr = new char[MAX_PATH_EX];
// 		sprintf_s(InfoStr, MAX_PATH_EX, "%lu", m_Filesize);

// 		char* TmpBuffer = new char[DATASTRINGMESSAGELEN];
// 		memset(TmpBuffer, '\x0', DATASTRINGMESSAGELEN);
// 		memcpy(TmpBuffer, InfoStr, strlen(InfoStr));

// 		/*Sendret = socketsend->SendMessageToServer(functionName_GiveExplorerData, TmpBuffer);*/
// 		Sendret = 1;
// 		if (Sendret > 0)
// 		{
// 			DWORD readsize;
// 			BYTE* buffer = new BYTE[m_Filesize];
// 			ReadFile(m_File, buffer, m_Filesize, &readsize, NULL);
// 			if (m_Filesize > DATASTRINGMESSAGELEN) {
// 				DWORD tmplen = m_Filesize;
// 				for (DWORD i = 0; i < m_Filesize; i += DATASTRINGMESSAGELEN) {
// 					memset(TmpBuffer, '\x00', DATASTRINGMESSAGELEN);
// 					if (tmplen < DATASTRINGMESSAGELEN) { memcpy(TmpBuffer, buffer + i, tmplen); }
// 					else {
// 						memcpy(TmpBuffer, buffer + i, DATASTRINGMESSAGELEN);
// 						tmplen -= DATASTRINGMESSAGELEN;
// 					}

// 					Sendret = GiveExplorerData(TmpBuffer, tcpSocket);
// 					if (Sendret == 0 || Sendret == -1) break;
// 				}
// 				memset(TmpBuffer, '\x00', DATASTRINGMESSAGELEN);
// 			}
// 			else
// 			{
// 				//unsigned char* buff = new unsigned char[DATASTRINGMESSAGELEN];
// 				printf("DATASTRINGMESSAGELEN else\n");
// 				memset(TmpBuffer, '\x00', DATASTRINGMESSAGELEN);
// 				memcpy(TmpBuffer, buffer, m_Filesize);

// 				Sendret = GiveExplorerData(TmpBuffer, tcpSocket);
// 				memset(TmpBuffer, '\x00', DATASTRINGMESSAGELEN);

// 			}
// 			delete[] buffer;
// 		}

// 		if (Sendret > 0)
// 		{
// 			memset(TmpBuffer, '\x00', DATASTRINGMESSAGELEN);

// 			Sendret = GiveExplorerData(TmpBuffer, tcpSocket);
// 			wchar_t* m_Path = new wchar_t[MAX_PATH_EX];
// 			GetMyPath(m_Path);
// 			CloseHandle(m_File);

// 		}
// 	}
// 	else
// 	{
// 		log.logger("Error", "failed to send zip file\n");
// 		BYTE* TmpBuffer = new BYTE[DATASTRINGMESSAGELEN];
// 		memset(TmpBuffer, '\x00', DATASTRINGMESSAGELEN);
// 		delete[] TmpBuffer;
// 	}
// }

// int Task::Explorer(char* buff, SOCKET* tcpSocket) {
// 	char* functionName = new char[24];
// 	strcpy_s(functionName, 24, "Explorer");
// 	return socketsend->SendDataToServer(functionName, buff, tcpSocket);
// }
// int Task::GiveExplorerInfo(char* buff, SOCKET* tcpSocket) {
// 	char* functionName = new char[24];
// 	strcpy_s(functionName, 24, "GiveExplorerInfo");
// 	return socketsend->SendDataToServer(functionName, buff, tcpSocket);
// }
// int Task::GiveExplorerProgress(char* buff, SOCKET* tcpSocket) {
// 	char* functionName = new char[24];
// 	strcpy_s(functionName, 24, "GiveExplorerProgress");
// 	return socketsend->SendDataToServer(functionName, buff, tcpSocket);
// }
// int Task::GiveExplorerData(char* buff, SOCKET* tcpSocket) {
// 	char* functionName = new char[24];
// 	strcpy_s(functionName, 24, "GiveExplorerData");
// 	return socketsend->SendDataToServer(functionName, buff, tcpSocket);
// } 
// int Task::GiveExplorerEnd(char* buff, SOCKET* tcpSocket) {
// 	char* functionName = new char[24];
// 	strcpy_s(functionName, 24, "GiveExplorerEnd");
// 	return socketsend->SendDataToServer(functionName, buff, tcpSocket);
// }
// int Task::GiveExplorerError(char* buff, SOCKET* tcpSocket) {
// 	char* functionName = new char[24];
// 	strcpy_s(functionName, 24, "GiveExplorerError");
// 	return socketsend->SendDataToServer(functionName, buff, tcpSocket);
// }


// // collect 
// int Task::GetCollectInfo(StrPacket* udata) { 
// 	DWORD CollectProcessPid = 0;
// 	TCHAR* RunExeStr = new TCHAR[MAX_PATH];
// 	TCHAR* RunComStr = new TCHAR[512];
// 	GetModuleFileName(GetModuleHandle(NULL), RunExeStr, MAX_PATH);

// 	//TCHAR MyName[MAX_PATH];
// 	//swprintf_s(MyName, MAX_PATH, L"%hs", "./Agent_VS2019");
// 	wstring filename = tool.GetFileName();
// 	TCHAR MyName[MAX_PATH];
// 	wcscpy_s(MyName, filename.c_str());
// 	TCHAR ServerIP[MAX_PATH];
// 	swprintf_s(ServerIP, MAX_PATH, L"%hs", info->ServerIP);

// 	swprintf_s(RunComStr, 512, L"\"%s\" %s %d Collect", MyName, ServerIP, info->Port);
// 	wprintf(L"Run Process: %ls\n", RunComStr);
// 	RunProcessEx(RunExeStr, RunComStr, 1024, FALSE, FALSE, CollectProcessPid);

// 	info->processMap["Collect"] = CollectProcessPid;
// 	log.logger("Debug", "Collect enabled");
	
// 	return 1; 
// }
// int Task::CollectionComputerInfo()

// {
// 	//SOCKET* tcpSocket = CreateNewSocket();
// 	//if (tcpSocket == nullptr) return 0;

// 	printf("start collect...\n");
// 	std::remove("collectcomputerinfo.db");

// 	Collect* collect = new Collect;
// 	wchar_t* m_FullDbPath = new wchar_t[MAX_PATH_EX];
// 	GetMyPath(m_FullDbPath);
// 	_tcscat_s(m_FullDbPath, MAX_PATH_EX, _T("\\collectcomputerinfo.db"));

// 	if (_waccess(m_FullDbPath, 00)) {
// 		CreateProcessForCollection(m_FullDbPath, info->tcpSocket);
// 		wchar_t* ConfigPath = new wchar_t[MAX_PATH_EX];
// 		GetMyPath(ConfigPath);
// 		_tcscat_s(ConfigPath, MAX_PATH_EX, _T("\\predefine.config"));
// 		map<string, vector<PredefineObj>> mapPredefine;
// 		if (LoadPredefineConfig(ConfigPath, &mapPredefine))
// 		{
// 			char* InfoStr = new char[MAX_PATH_EX];
// 			InsertFromToInCombination(m_FullDbPath, &mapPredefine, info->tcpSocket);
// 		}

// 		if (!_waccess(m_FullDbPath, 00))
// 		{
// 			TCHAR* collectcomputerinfo_db = new TCHAR[MAX_PATH_EX];
// 			GetMyPath(collectcomputerinfo_db);
// 			_tcscat_s(collectcomputerinfo_db, MAX_PATH_EX, _T("\\collectcomputerinfo.db"));

// 			TCHAR* Collect_zip = new TCHAR[MAX_PATH_EX];
// 			GetMyPath(Collect_zip);
// 			_tcscat_s(Collect_zip, MAX_PATH_EX, _T("\\Collect.zip"));

// 			if (tool.CompressFileToZip(Collect_zip, collectcomputerinfo_db)) _tprintf(_T("File compressed and added to ZIP successfully.\n"));
// 			else _tprintf(_T("Failed to compress and add file to ZIP.\n"));

// 			SendDbFileToServer(Collect_zip, info->tcpSocket);
// 			DeleteFile(m_FullDbPath);
// 			DeleteFile(Collect_zip);
// 			//if (std::remove("Collect.zip") != 0) perror("Error delete Explorer.zip\n");
// 		}
// 		else {
// 			printf("m_FullDbPath failed\n");
// 		}
// 		delete[] ConfigPath;
// 	}
// 	delete[] m_FullDbPath;

// 	//closesocket(*tcpSocket);
// 	return 1;
// }
// bool Task::LoadPredefineConfig(TCHAR* ConfigPath, map<string, vector<PredefineObj>>* mapPredefine)
// {
// 	bool bResult = false;
// 	if (!_waccess(ConfigPath, 00))
// 	{
// 		fstream fin;
// 		fin.open(ConfigPath, ios::in);
// 		{
// 			char* linestr = new char[STRPACKETSIZE];
// 			string DefineName, TableName, OutStr;
// 			while (fin.getline(linestr, STRPACKETSIZE, '\n'))
// 			{
// 				DefineName.clear();
// 				vector<PredefineObj> tmpVec;
// 				ParsePredefineConfig(linestr, &DefineName, &tmpVec);
// 				if (!DefineName.empty() && tmpVec.size() > 0)
// 				{
// 					mapPredefine->insert(pair<string, vector<PredefineObj>>(DefineName, tmpVec));
// 				}
// 			}
// 		}
// 		fin.close();
// 		if (mapPredefine->size() > 0)
// 		{
// 			bResult = true;
// 		}
// 	}
// 	else {
// 		printf("LoadPredefineConfig failed\n");
// 	}
// 	return bResult;
// }
// void Task::ParsePredefineConfig(char* str, string* defineName, vector<PredefineObj>* Vmp)
// {
// 	char* psc;
// 	char* next_token = NULL;
// 	bool bFirst = true;
// 	psc = strtok_s(str, ";", &next_token);

// 	while (psc != NULL)
// 	{
// 		if (bFirst == true)
// 		{
// 			*defineName = psc;
// 			bFirst = false;
// 		}
// 		else
// 		{
// 			char* subStr;
// 			char* next_token_subStr = NULL;
// 			subStr = strtok_s(psc, "|", &next_token_subStr);
// 			char* next_token_client = NULL;
// 			subStr = strtok_s(subStr, ",", &next_token_client);
// 			vector<string> vecClients;
// 			while (subStr != NULL)
// 			{
// 				string client = subStr;
// 				vecClients.push_back(client);
// 				subStr = strtok_s(NULL, ",", &next_token_client);
// 			}

// 			subStr = strtok_s(psc, "|", &next_token_subStr);
// 			string TableName = subStr;
// 			subStr = strtok_s(NULL, "|", &next_token_subStr);
// 			string FilterStr = subStr;
// 			PredefineObj tmpObj;
// 			//TableName.erase(std::remove_if(TableName.begin(), TableName.end(), isspace), TableName.end());
// 			TableName.erase(std::remove_if(TableName.begin(), TableName.end(), [](char c) {
// 				return std::isspace(static_cast<unsigned char>(c));
// 				}), TableName.end());

// 			tmpObj.TableName = TableName;
// 			tmpObj.vecFilterCondition = FilterStr;
// 			if (!tmpObj.TableName.empty() && !tmpObj.vecFilterCondition.empty())
// 			{
// 				Vmp->push_back(tmpObj);
// 			}
// 		}
// 		psc = strtok_s(NULL, ";", &next_token);
// 	}
// }
// bool Task::InsertFromToInCombination(TCHAR* DBName, const map<string, vector<PredefineObj>>* mapPredefine, SOCKET* tcpSocket)
// {
// 	Collect* collect = new Collect;
// 	char* functionName = new char[24];
// 	strcpy_s(functionName, 24, "GiveCollectProgress");

// 	bool bResult = false;
// 	sqlite3* m_db;
// 	string query;
// 	if (!sqlite3_open16(DBName, &m_db))
// 	{
// 		for (auto& Predefine : *mapPredefine)
// 		{
// 			query.clear();
// 			query = "CREATE TABLE ";
// 			query += Predefine.first;
// 			query += " (id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT, ip TEXT, \
// 													table_id INTEGER, item TEXT, date TEXT, type TEXT, etc TEXT)";
// 			// 可能已存在，所以不判斷建成功失敗 或者進去調整function
// 			collect->WriteSQLiteDB(m_db, (char*)query.c_str());
// 			for (auto& TableFilter : Predefine.second)
// 			{
// 				query.clear();
// 				if (GetQueryByTable(&query, TableFilter.TableName, TableFilter.vecFilterCondition))
// 				{
// 					vector<CombineObj> vecCombineObj;
// 					collect->GetDataByQuery(query, m_db, &vecCombineObj);
// 					int id = 0;
// 					query.clear();
// 					query = "SELECT MAX(id) FROM";
// 					query += Predefine.first;

// 					sqlite3_stmt* statement;
// 					if (sqlite3_prepare(m_db, query.c_str(), -1, &statement, 0) == SQLITE_OK)
// 					{
// 						int res = 0;
// 						if (res != SQLITE_DONE && res != SQLITE_ERROR)
// 						{
// 							res = sqlite3_step(statement);
// 							if (res == SQLITE_ROW)
// 							{
// 								id = sqlite3_column_int(statement, 0);
// 							}
// 						}
// 					}
// 					sqlite3_finalize(statement);
// 					collect->WriteDataSetToDB(m_db, vecCombineObj, Predefine.first, info->MAC, info->IP, TableFilter.TableName, id);
// 				}
// 			}
// 		}

// 		char* InfoStr = new char[MAX_PATH_EX];
// 		//BYTE* TmpBuffer = new BYTE[DATASTRINGMESSAGELEN];
// 		char* TmpBuffer = new char[STRINGMESSAGELEN];
// 		memset(InfoStr, '\0', MAX_PATH_EX);
// 		sprintf_s(InfoStr, MAX_PATH_EX, "%d/%d", 35, 35);
// 		memset(TmpBuffer, '\x0', STRINGMESSAGELEN);
// 		memcpy(TmpBuffer, InfoStr, strlen(InfoStr));

// 		int Sendret = GiveCollectProgress(TmpBuffer, tcpSocket);
// 		//auto Sendret = SendDataBufToServer(MyMAC, MyIP, "GiveCollectProgress", TmpBuffer);
// 	}
// 	sqlite3_close(m_db);
// 	return bResult;
// }
// bool Task::GetQueryByTable(string* query, string TableName, string QueryFilter)
// {
// 	bool bResult = true;
// 	*query += "SELECT ";
// 	if (TableName == "ARPCache") { *query += "id, internetaddress, physicaladdress "; }
// 	else if (TableName == "BaseService") { *query += "id, name, pathname FROM "; }
// 	else if (TableName == "ChromeDownload") { *query += "id, download_url, start_time, target_path "; }
// 	else if (TableName == "ChromeHistory") { *query += "id, url, last_visit_time, title FROM "; }
// 	else if (TableName == "ChromeKeywordSearch") { *query += "id, term, title FROM "; }
// 	else if (TableName == "ChromeLogin") { *query += "id, origin_url, date_created, username_value "; }
// 	else if (TableName == "EventApplication") { *query += "id, eventid, createdsystemtime, evtrenderdata "; }
// 	else if (TableName == "EventSecurity") { *query += "id, eventid, createdsystemtime, evtrenderdata "; }
// 	else if (TableName == "EventSystem") { *query += "id, eventid, createdsystemtime, evtrenderdata "; }
// 	else if (TableName == "FirefoxHistory") { *query += "id, url, last_visit_time, title "; }
// 	else if (TableName == "FirefoxLogin") { *query += "id, hostname, timelastused, username "; }
// 	else if (TableName == "IECache") { *query += "id, sourceurlname, lastaccesstime, localfilename "; }
// 	else if (TableName == "IEHistory") { *query += "id, url, visitedtime, title "; }
// 	else if (TableName == "InstalledSoftware") { *query += "id, displayname, registrytime, publisher "; }
// 	else if (TableName == "MUICache") { *query += "id, applicationpath, applicationname "; }
// 	else if (TableName == "Network") { *query += "id, processname, remoteaddress "; }
// 	else if (TableName == "NetworkResources") { *query += "id, resourcesname, ipaddress "; }
// 	else if (TableName == "OpenedFiles") { *query += "id, processname, processid "; }
// 	else if (TableName == "Prefetch") { *query += "id, processname, lastruntime, processpath "; }
// 	else if (TableName == "Process") { *query += "id, process_name, processcreatetime, process_path "; }
// 	else if (TableName == "RecentFile") { *query += "id, name, accesstime, fullpath "; }
// 	else if (TableName == "Service") { *query += "id, name, pathname "; }
// 	else if (TableName == "ShellBags") { *query += "id, path, lastmodifiedtime, slotpath "; }
// 	else if (TableName == "Shortcuts") { *query += "id, shortcutname, modifytime, linkto "; }
// 	else if (TableName == "StartRun") { *query += "id, name, command "; }
// 	else if (TableName == "SystemInfo") { *query += "id, hotfix, os "; }
// 	else if (TableName == "TaskSchedule") { *query += "id, name, lastruntime, path "; }
// 	else if (TableName == "USBdevices") { *query += "id, device_description, last_arrival_date, device_letter "; }
// 	else if (TableName == "UserAssist") { *query += "id, name, modifiedtime, of_times_executed "; }
// 	else if (TableName == "UserProfiles") { *query += "id, username, lastlogontime, usersid "; }
// 	else if (TableName == "Wireless") { *query += "id, profilename, lastmodifiedtime, authentication "; }
// 	else if (TableName == "JumpList") { *query += "id, fullpath, recordtime, application_id "; }
// 	else if (TableName == "WindowsActivity") { *query += "id, app_id, last_modified_on_client, activity_type "; }
// 	else if (TableName == "NetworkDataUsageMonitor") { *query += "id, app_name, timestamp, bytes_sent "; }
// 	else if (TableName == "AppResourceUsageMonitor") { *query += "id, app_name, timestamp, backgroundbyteswritten "; }
// 	else { bResult = false; }

// 	if (bResult == true)
// 	{
// 		*query += "FROM ";
// 		*query += TableName;
// 		if (!QueryFilter.empty())
// 		{
// 			*query += " WHERE ";
// 			*query += QueryFilter;
// 		}
// 	}

// 	return bResult;
// }
// void Task::CreateProcessForCollection(TCHAR* DBName, SOCKET* tcpSocket)
// {
// 	Collect* collect = new Collect;

// 	TCHAR* RunExeStr = new TCHAR[MAX_PATH];
// 	TCHAR* RunComStr = new TCHAR[512];
// 	GetModuleFileName(GetModuleHandle(NULL), RunExeStr, MAX_PATH);

// 	int Sendret;
// 	char* InfoStr = new char[MAX_PATH_EX];
// 	char* TmpBuffer = new char[DATASTRINGMESSAGELEN];

// 	int iLen = sizeof(collect->CollectionNums) / sizeof(collect->CollectionNums[0]);

// 	printf("start collect...\n");
// 	for (int i = 0; i < iLen; i++) {

// 		TCHAR* m_FilePath = new TCHAR[MAX_PATH_EX];
// 		GetMyPath(m_FilePath);
// 		_tcscat_s(m_FilePath, MAX_PATH_EX, _T("\\Collection.dll")); // Collection-x64.dll
// 		HMODULE m_lib = LoadLibrary(m_FilePath);
// 		if (m_lib) {
// 			printf("load dll success : %d\n", i);
// 			TCHAR buffer[20]; // Adjust the buffer size as needed
// 			_sntprintf_s(buffer, sizeof(buffer) / sizeof(TCHAR), _T("%d"), collect->CollectionNums[i]);
// 			TCHAR* tcharString = buffer;

// 			try {
// 				collect->CollectionProcess(m_lib, DBName, tcharString);
// 			}
// 			catch (...) {
// 				printf("collect failed\n");
// 			}
			
// 			FreeLibrary(m_lib);
// 		}
// 		else {
// 			printf("load dll failed\n");
// 			log.logger("Error", "collection load dll failed\n");
// 		}

// 		memset(InfoStr, '\0', MAX_PATH_EX);
// 		sprintf_s(InfoStr, MAX_PATH_EX, "%d/%d", i + 1, iLen);
// 		memset(TmpBuffer, '\x0', DATASTRINGMESSAGELEN);
// 		memcpy(TmpBuffer, InfoStr, strlen(InfoStr));

// 		GiveCollectProgress(TmpBuffer, tcpSocket);

// 	}
// 	//delete[] InfoStr;
// 	delete[] RunComStr;
// 	delete[] RunExeStr;
// }
// void Task::SendDbFileToServer(const TCHAR* DBName, SOCKET* tcpSocket)
// {
// 	HANDLE m_File = CreateFile(DBName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
// 	if (m_File != INVALID_HANDLE_VALUE) {
// 		DWORD m_Filesize = GetFileSize(m_File, NULL);
// 		int Sendret;
// 		char* InfoStr = new char[MAX_PATH_EX];
// 		sprintf_s(InfoStr, MAX_PATH_EX, "%lu", m_Filesize);
// 		char* TmpBuffer = new char[DATASTRINGMESSAGELEN];
// 		memset(TmpBuffer, '\x0', DATASTRINGMESSAGELEN);
// 		memcpy(TmpBuffer, InfoStr, strlen(InfoStr));

// 		Sendret = GiveCollectDataInfo(TmpBuffer, tcpSocket);

// 		if (Sendret > 0)
// 		{
// 			DWORD readsize;
// 			BYTE* buffer = new BYTE[m_Filesize];
// 			ReadFile(m_File, buffer, m_Filesize, &readsize, NULL);
// 			if (m_Filesize > DATASTRINGMESSAGELEN) {
// 				DWORD tmplen = m_Filesize;
// 				for (DWORD i = 0; i < m_Filesize; i += DATASTRINGMESSAGELEN) {
// 					memset(TmpBuffer, '\x00', DATASTRINGMESSAGELEN);
// 					if (tmplen < DATASTRINGMESSAGELEN) memcpy(TmpBuffer, buffer + i, tmplen);
// 					else {
// 						memcpy(TmpBuffer, buffer + i, DATASTRINGMESSAGELEN);
// 						tmplen -= DATASTRINGMESSAGELEN;
// 					}

// 					Sendret = GiveCollectData(TmpBuffer, tcpSocket);
// 					if (Sendret == 0 || Sendret == -1) break;
// 				}
// 				memset(TmpBuffer, '\x00', DATASTRINGMESSAGELEN);
// 			}
// 			else
// 			{
// 				memset(TmpBuffer, '\x00', DATASTRINGMESSAGELEN);
// 				memcpy(TmpBuffer, buffer, m_Filesize);
// 				Sendret = GiveCollectData(TmpBuffer, tcpSocket);
// 				memset(TmpBuffer, '\x00', DATASTRINGMESSAGELEN);
// 			}
// 			delete[] buffer;
// 		}
// 		if (Sendret > 0)
// 		{
// 			memset(TmpBuffer, '\x00', DATASTRINGMESSAGELEN);
// 			Sendret = GiveCollectDataEnd(TmpBuffer, tcpSocket);

// 			wchar_t* m_Path = new wchar_t[MAX_PATH_EX];
// 			GetMyPath(m_Path);
// 			tool.DeleteAllCsvFiles(m_Path);
// 			CloseHandle(m_File);

// 		}
// 	}
// 	else
// 	{
// 		printf("DB file not exists\n");
// 		//BYTE* TmpBuffer = new BYTE[DATASTRINGMESSAGELEN];
// 		//memset(TmpBuffer, '\x00', DATASTRINGMESSAGELEN);
// 		////SendDataBufToServer(MyMAC, MyIP, "GiveCollectDataError", TmpBuffer);
// 		//delete[] TmpBuffer;
// 	}
// }

// int Task::GiveCollectProgress(char* buff, SOCKET* tcpSocket) {
// 	char* functionName = new char[24];
// 	strcpy_s(functionName, 24, "GiveCollectProgress");
// 	printf("%s\n", buff);
// 	return socketsend->SendDataToServer(functionName, buff, tcpSocket);
// }
// int Task::GiveCollectDataInfo(char* buff, SOCKET* tcpSocket) {
// 	char* functionName = new char[24];
// 	strcpy_s(functionName, 24, "GiveCollectDataInfo");
// 	printf("%s\n", buff);
// 	return socketsend->SendDataToServer(functionName, buff, tcpSocket);
// }
// int Task::GiveCollectData(char* buff, SOCKET* tcpSocket) {
// 	char* functionName = new char[24];
// 	strcpy_s(functionName, 24, "GiveCollectData");
// 	printf("%s\n", buff);
// 	return socketsend->SendDataToServer(functionName, buff, tcpSocket);
// }
// int Task::GiveCollectDataEnd(char* buff, SOCKET* tcpSocket) {
// 	char* functionName = new char[24];
// 	strcpy_s(functionName, 24, "GiveCollectDataEnd");
// 	printf("%s\n", buff);
// 	return socketsend->SendDataToServer(functionName, buff, tcpSocket);
// }


// SOCKET* Task::CreateNewSocket() {
// 	WSADATA wsaData;
// 	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
// 		std::cerr << "Failed to initialize Winsock." << std::endl;
// 		return nullptr;
// 	}

// 	SOCKET* tcpSocket = new SOCKET;
// 	*tcpSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
// 	if (*tcpSocket == INVALID_SOCKET) {
// 		std::cerr << "Error creating TCP socket: " << WSAGetLastError() << std::endl;
// 		WSACleanup();
// 		return nullptr;
// 	}

// 	sockaddr_in serverAddr;
// 	serverAddr.sin_family = AF_INET;
// 	serverAddr.sin_port = htons(1989);
// 	serverAddr.sin_addr.s_addr = inet_addr(info->ServerIP);
// 	//serverAddr.sin_addr.s_addr = inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr);

// 	if (connect(*tcpSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
// 		std::cerr << "Error connecting to server: " << WSAGetLastError() << std::endl;
// 		closesocket(*tcpSocket);
// 		WSACleanup();
// 		return nullptr;
// 	}

// 	return tcpSocket;
// }
// int Task::DataRight(StrPacket* udata) { return 1; }
