#include "socket_manager.h"
#include "caes.h"
#include <iostream>


#include <string>
#include <cstring>
#include <future>



SocketManager::SocketManager(std::string& serverIP, int port, Info* infoInstance, SocketSend* socketSendInstance) {

    Port = port;
    InfoInstance = infoInstance;
    task = new Task(infoInstance, socketSendInstance);
    InfoInstance->tcpSocket = tcpSocket;
    InfoInstance->Port = port;
    strcpy(InfoInstance->ServerIP, serverIP.c_str());

    if (!connectTCP(serverIP, port)) perror("connection failed\n");
    else printf("connect success\n");

    getSystemInfo();

    // until the end
    // closesocket(tcpSocket);

}

void SocketManager::getSystemInfo() {
    GetIPAndMAC(InfoInstance->MAC, InfoInstance->IP, InfoInstance->ServerIP);
}

bool SocketManager::connectTCP(const std::string& serverIP, int port) {
    tcpSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (tcpSocket == -1) {
        perror("Error creating TCP socket");
        return false;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = inet_addr(serverIP.c_str());

    while (connect(tcpSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    InfoInstance->tcpSocket = tcpSocket;

    return true;
}
void SocketManager::receiveTCP() {
    
    printf("Receive Thread Enabled\n");
    int FirstTime = 0;
    while (true) {
        if (FirstTime) {
            printf("wait for server to reconnect...");
            log.logger("Info", "wait for server to reconnect...\n");

            for (auto& pair : InfoInstance->processMap) {
                if (pair.first != "Log" && pair.second != 0) {
                    std::string LogMsg = "kill " + pair.first + " process";
                    log.logger("Debug", LogMsg);

                    std::string killCommand = "kill -9 " + std::to_string(pair.second);
                    int result = std::system(killCommand.c_str());
                }
            }

            if (!connectTCP(InfoInstance->ServerIP, InfoInstance->Port)) perror("connection failed\n");
            else log.logger("Info", "server reconnect success");
            HandleTaskToServer("GiveInfo");
        }

        FirstTime = 1;
        while (true) {
            char buff[STRPACKETSIZE];
            int ret = recv(tcpSocket, buff, sizeof(buff), 0);
            if (ret <= 0) break;

            SetKeys(BIT128, AESKey);
            DecryptBuffer((BYTE*)buff, STRPACKETSIZE);
            StrPacket* udata;
            udata = (StrPacket*)buff;

            std::cout << "Receive: " << udata->DoWorking << std::endl;

            std::string Task(udata->DoWorking);
            std::string LogMsg = "Receive: " + Task;
            log.logger("Info", LogMsg);

            if (!HandleTaskFromServer(udata)) break;
        }
    }
    
    printf("Receive Thread Close\n");


}
void SocketManager::closeTCP() {
    if (tcpSocket != -1) close(tcpSocket);
}
void SocketManager::HandleTaskToServer(std::string functionName) {
    
    if (task->functionMap.count(functionName) > 0) {
        int ret;
        std::any argument;
        ret = task->functionMap[functionName](task, argument);
        if (!ret) std::cout << functionName << " send failed" << std::endl;
    }
    else std::cout << functionName << " Function not found" << std::endl;
}
int SocketManager::HandleTaskFromServer(StrPacket* udata) {

    int ret = 0;
    if (task->functionFromServerMap.count(udata->DoWorking) > 0) {
        ret = task->functionFromServerMap[udata->DoWorking](task, udata);
    }
    else std::cout << "Function not found" << std::endl;

    return ret;
}





