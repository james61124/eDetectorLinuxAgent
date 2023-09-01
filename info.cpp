#include "info.h"

Info::Info() {
    DetectProcess = 0;
    DetectNetwork = 0;
    Port = 1234;
    DetectPort = 1235;
    tcpSocket = 0;

    char* KeyNum = new char[36];
    std::strcpy(KeyNum, "NoKey");
    GetThisClientKey(KeyNum);
    std::strcpy(UUID, KeyNum);

}