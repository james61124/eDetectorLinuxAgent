#ifndef TOOLS_H
#define TOOLS_H

#include <vector>
#include <string>
#include <cstring>
#include <Windows.h>
#include <codecvt>
#include <lmcons.h>
#include <memory>
#include <iostream>
#include <set>
#include <map>

#include <Ntstatus.h>
#include <winternl.h>  
#include <Psapi.h> 
#include <tchar.h>
#include <Sddl.h>
#include <Shobjidl.h>
#include <wintrust.h>
#include <dbghelp.h>
#include <Iphlpapi.h>
#include <ctime>   // For std::time
#include <cwchar>  // For std::wcsftime

#include <fstream>
#include <thread>
#include <queue>

#include "zip.h"
#include "GlobalFunction.h"

// #include "StrPacket.h"
//#include "Process.h"
// #include "PeFunction.h"





typedef void (WINAPI* PGNSI)(LPSYSTEM_INFO);

class Tool {
public:

    std::vector<std::string> SplitMsg(char* msg);
    time_t FileTimeToUnixTime(const FILETIME& ft);

    char* StringToCharPointer(std::string msg);
    char* WideStringToUTF8(const std::wstring& wideString);
    void DeleteAllCsvFiles(wchar_t* directoryPath);
    
    wstring GetFileName();

    // Get System Info
    char* GetSysInfo();
    char* GetComputerNameUTF8();
    char* GetUserNameUTF8();
    char* GetOSVersion();
    unsigned long long GetBootTime();
    bool CompressFileToZip(const TCHAR* zipFileName, const TCHAR* sourceFilePath);

    // Process

    void LoadApiPattern(std::set<DWORD>* pApiName);

    const char* WideCharToConstChar(const wchar_t* wideString);
    LPCSTR WideCharToLPCWSTR(wchar_t* wideString);
    wchar_t* CharPtrToWideCharPtr(char* multiByteString);
    char* Convert2State(DWORD dwState);
    bool SetRegistryValue(const wchar_t* valueName, const wchar_t* valueData);
    std::wstring GetRegistryValue(const wchar_t* valueName);

};


#endif