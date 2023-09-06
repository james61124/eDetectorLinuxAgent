#ifndef TOOLS_H
#define TOOLS_H

#include <vector>
#include <string>
#include <cstring>
#include <iostream>


// #include "StrPacket.h"
//#include "Process.h"
// #include "PeFunction.h"



class Tool {
public:

    std::vector<std::string> SplitMsg(char* msg);
    // time_t FileTimeToUnixTime(const FILETIME& ft);

    // char* StringToCharPointer(std::string msg);
    // char* WideStringToUTF8(const std::wstring& wideString);
    // void DeleteAllCsvFiles(wchar_t* directoryPath);
    
    // wstring GetFileName();

    // // Get System Info
    // char* GetSysInfo();
    // char* GetComputerNameUTF8();
    // char* GetUserNameUTF8();
    // char* GetOSVersion();
    // unsigned long long GetBootTime();
    // bool CompressFileToZip(const TCHAR* zipFileName, const TCHAR* sourceFilePath);

    // // Process

    // void LoadApiPattern(std::set<DWORD>* pApiName);

    // const char* WideCharToConstChar(const wchar_t* wideString);
    // LPCSTR WideCharToLPCWSTR(wchar_t* wideString);
    // wchar_t* CharPtrToWideCharPtr(char* multiByteString);
    // char* Convert2State(DWORD dwState);
    // bool SetRegistryValue(const wchar_t* valueName, const wchar_t* valueData);
    // std::wstring GetRegistryValue(const wchar_t* valueName);

};


#endif