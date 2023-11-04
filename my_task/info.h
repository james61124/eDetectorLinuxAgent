#pragma once
#ifndef INFO_H
#define INFO_H

#include "StrPacket.h"
#include <unordered_map>
#include <cstring> 

class Info {
public:
    Info();

    int Port;
    int DetectPort;
    char MAC[MACLEN];
    char IP[IPLEN];
    char UUID[UUIDLEN];
    int DetectProcess = 0;
    int DetectNetwork = 0;
    int Scan = 0;

    char ServerIP[IPLEN];

    int tcpSocket;

    std::unordered_map<std::string, pid_t> processMap;

};

#endif