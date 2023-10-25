#ifndef TASK_H
#define TASK_H


#include <unordered_map>
#include <functional>
#include <any>
#include <set>
#include <map>
#include <fstream>
#include <sys/utsname.h>
#include <sys/stat.h>

#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>

// #include "tools.h"
#include "socket_send.h"
#include "info.h"
#include "scan.h"
#include "Log.h"
#include "StrPacket.h"
#include "explorer.h"




class Task {
public:

    Task(Info* infoInstance, SocketSend* socketSendInstance);
    Info* info;
    SocketSend* socketsend;

    using FunctionPtr = std::function<int(Task*, std::any)>;
    using FunctionPtrFromServer = std::function<int(Task*, StrPacket*)>;

    std::unordered_map<std::string, FunctionPtr> functionMap;
    std::unordered_map<std::string, FunctionPtrFromServer> functionFromServerMap;

    std::unordered_map<std::string, std::thread> threadMap;
    void startThread(const std::string& key, std::string functionName);

    // handshake
    int GiveInfo();
    int GiveDetectInfoFirst();
    int GiveDetectInfo();
    int OpenCheckthread(StrPacket* udata);
    int UpdateDetectMode(StrPacket* udata);
    int CheckConnect();

    // // detect
    void DetectProcess();
    // int DetectProcess_();
    // int GiveDetectProcess(char* buff, SOCKET* tcpSocket);
    // int GiveDetectProcessFrag(char* buff, SOCKET* tcpSocket);
    // int GiveDetectNetwork(char* buff, SOCKET* tcpSocket);
    

    // scan
    int GetScan(StrPacket* udata);
    int GiveProcessData();

    // image
    int GetImage(StrPacket* udata);
    int SearchImageFile();

    int GetDrive(StrPacket* udata);
    int ExplorerInfo(StrPacket* udata);
    int GiveExplorerData();

    
    // int GiveScanFragment(char* buff, SOCKET* tcpSocket);
    // int GiveScanEnd(char* buff, SOCKET* tcpSocket);
    // int GiveScanProgress(char* buff, SOCKET* tcpSocket);

    // // explorer
    // int ExplorerInfo_(StrPacket* udata);
    // int GiveDriveInfo();
    // int Explorer(char* buff, SOCKET* tcpSocket);
    // int GiveExplorerInfo(char* buff, SOCKET* tcpSocket);
    // int GiveExplorerData(char* Drive, char* FileSystem);
    // int GiveExplorerProgress(char* buff, SOCKET* tcpSocket);
    // int GiveExplorerData(char* buff, SOCKET* tcpSocket);
    // int GiveExplorerEnd(char* buff, SOCKET* tcpSocket);
    // int GiveExplorerError(char* buff, SOCKET* tcpSocket);

    // //collect
    // int GiveCollectDataInfo(char* buff, SOCKET* tcpSocket);
    // int GiveCollectProgress(char* buff, SOCKET* tcpSocket);
    // int GiveCollectData(char* buff, SOCKET* tcpSocket);
    // int GiveCollectDataEnd(char* buff, SOCKET* tcpSocket);


   
    
    
    // int GetScanInfoData_(StrPacket* udata);
    
    // int GetProcessInfo(StrPacket* udata);
    // int GetDrive(StrPacket* udata);
    // //int ExplorerInfo(StrPacket* udata);
    // int GetCollectInfo(StrPacket* udata);
    // int GetCollectInfoData(StrPacket* udata);
    // int DataRight(StrPacket* udata);

    // SOCKET* CreateNewSocket();
    // int DetectNewNetwork(int pMainProcessid);

private:
    
    Tool tool;
    Log log;

    int SendZipFileToServer(const char* feature, const char* zipFileName);
    int SendDataPacketToServer(const char* function, char* buff);
    int SendMessagePacketToServer(const char* function, char* buff);
    int CreateNewSocket();

    // // scan
    // void GiveScanDataSendServer(char* pMAC, char* pIP, char* pMode, map<DWORD, ProcessInfoData>* pFileInfo, vector<UnKnownDataInfo>* pUnKnownData, SOCKET* tcpSocket);

    // // detect
    // int DetectProcessRisk(int pMainProcessid, bool IsFirst, set<DWORD>* pApiName, SOCKET* tcpSocket);
    // void SendProcessDataToServer(vector<ProcessInfoData>* pInfo, SOCKET* tcpSocket);

    // int NTFSSearch(wchar_t vol_name, char* pMAC, char* pIP, SOCKET* tcpSocket, char* Drive, char* FileSystem);
    // void SendZipFileToServer(const TCHAR* DBName, SOCKET* tcpSocket);

    
    // char* GetMyPCDrive();

    
    // void SendNetworkDetectToServer(vector<string>* pInfo);

    // // collect
    // int CollectionComputerInfo(); 
    // bool LoadPredefineConfig(TCHAR* ConfigPath, map<string, vector<PredefineObj>>* mapPredefine); 
    // void SendDbFileToServer(const TCHAR* DBName, SOCKET* tcpSocket);
    // bool GetQueryByTable(string* query, string TableName, string QueryFilter);
    // void ParsePredefineConfig(char* str, string* defineName, vector<PredefineObj>* Vmp);
    // void CreateProcessForCollection(TCHAR* DBName, SOCKET* tcpSocket);
    // bool InsertFromToInCombination(TCHAR* DBName, const map<string, vector<PredefineObj>>* mapPredefine, SOCKET* tcpSocket);
    


};

#endif