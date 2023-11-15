#ifndef TOOLS_H
#define TOOLS_H

#include <vector>
#include <string>
#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>


// #include "StrPacket.h"
//#include "Process.h"
// #include "PeFunction.h"



class Tool {
public:

    std::vector<std::string> SplitMsg(char* msg);
    bool GetIPAndMAC(const char* interfaceName, char* macAddress, char* ipAddress);

};


#endif