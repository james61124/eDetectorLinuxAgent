#ifndef SOCKETMANAGER_H
#define SOCKETMANAGER_H


#include <string>
#include <map>
#include <unordered_map>
#include <functional>
#include <any>


#include <vector>
#include <thread>
#include <mutex>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "info.h"
#include "task.h"
#include "Log.h"
#include "tools.h"

#define MACLEN 20
#define IPLEN 20
#define UUIDLEN 36

class SocketManager {
public:
    SocketManager(std::string& serverIP, int port, Info* infoInstance, SocketSend* socketSendInstance);
    Info* InfoInstance;
    int tcpSocket;

    std::mutex mapMutex;

    int Port;
    int DetectPort;
    char MAC[MACLEN];
    char IP[IPLEN];
    char UUID[UUIDLEN];
    const char* AESKey = "AES Encrypt Decrypt";
    int DetectProcess = 0;
    int DetectNetwork = 0;

    // std::unordered_map<std::string, std::thread> threadMap;
    // void startThread(const std::string& key, std::string functionName);
    std::unordered_map<std::string, int> processMap;
    

    void getSystemInfo();
    bool connectTCP(const std::string& serverIP, int port);
    void receiveTCP();
    void closeTCP();

    void HandleTaskToServer(std::string functionName);
    int HandleTaskFromServer(StrPacket* udata);

    Task* task;



private:
    Tool tool;
    Log log;
    

};

#endif
