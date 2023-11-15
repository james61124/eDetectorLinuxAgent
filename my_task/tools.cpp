#include "tools.h"
//#include <Windows.h>

bool Tool::GetIPAndMAC(const char* interfaceName, char* macAddress, char* ipAddress) {
    int sock;
    struct ifreq ifr;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    strncpy(ifr.ifr_name, "ens34", IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
        unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
        printf("MAC Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        snprintf(macAddress, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    } else {
        perror("ioctl");
    }

    if (ioctl(sock, SIOCGIFADDR, &ifr) == 0) {
        struct sockaddr_in *ip = (struct sockaddr_in *)&ifr.ifr_addr;
        printf("IP Address: %s\n", inet_ntoa(ip->sin_addr));
         snprintf(ipAddress, 16, "%s", inet_ntoa(ip->sin_addr));
    } else {
        perror("ioctl");
    }

    close(sock);

    return true;
}

std::vector<std::string> Tool::SplitMsg(char* msg) {
    std::vector<std::string> MsgAfterSplit;
    char* nextToken = nullptr;
    const char* delimiter = "|";

    // First call to strtok_s
    char* token = strtok(msg, delimiter);
    while (token != nullptr) {
        MsgAfterSplit.push_back(token);
        // Subsequent calls to strtok_s using the same context (nextToken)
        token = strtok(nullptr, delimiter);
    }
    return MsgAfterSplit;
}

