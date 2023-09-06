#ifndef SOCKETSEND_H
#define SOCKETSEND_H

#include "info.h"
#include "caes.h"
#include "tools.h"
#include "Log.h"

#include <iostream>

class SocketSend {
public:
    SocketSend(Info* infoInstance);
    const char* AESKey = "AES Encrypt Decrypt";
    Info* info;
    bool sendTCP(char* data, long len, int tcpSocket);
    int SendDataToServer(char* Work, char* Mgs, int tcpSocket);
    int SendMessageToServer(char* Work, char* Mgs);

    int receiveTCP(int tcpSocket);

private:
    Tool tool;
    Log log;
};

#endif