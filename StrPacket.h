#pragma once

#ifndef STRPACKET_H
#define STRPACKET_H

#include <set>
#include <string>
#include <cstring>

#define MACLEN 20
#define IPLEN 20
#define UUIDLEN 36
#define WORKLEN 24
#define STRINGMESSAGELEN 924 //-33
#define STRPACKETSIZE 1024
#define DATASTRINGMESSAGELEN 65436
#define STRDATAPACKETSIZE 65536

struct StrPacket
{
	char MAC[MACLEN];
	char IP[IPLEN];
	char UUID[UUIDLEN];
	char DoWorking[WORKLEN];
	char csMsg[STRINGMESSAGELEN];
};

struct StrDataPacket//64K
{
	char MAC[MACLEN];
	char IP[IPLEN];
	char UUID[UUIDLEN];
	char DoWorking[WORKLEN];
	char csMsg[DATASTRINGMESSAGELEN];
};

#endif

