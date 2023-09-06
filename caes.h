// MyAES.h: 目標的標頭檔。
#ifndef CAES_H
#define CAES_H

//#pragma once
#include <stdbool.h>

// using namespace std;
typedef unsigned char BYTE;

struct BYTE4 {
	BYTE w[4];
};

typedef enum ENUM_KeySize_ {
	BIT128 = 0,
	BIT192,
	BIT256
}ENUM_KEYSIZE;

void SubBytes();
void ShiftRows();
void MixColumns();
void AddRoundKey(int round);
void KeyExpansion();
void InvShiftRows();
void InvSubBytes();
void InvMixColumns();
BYTE GfCalc(BYTE b, int Mode);
void Encrypt(BYTE* input, BYTE* output);
void Decrypt(BYTE* input, BYTE* output);

void create_CAES();
void del_CAES();
bool SetKeys(int KeySize, const char* sKey);
void EncryptBuffer(BYTE* input, int length);
void DecryptBuffer(BYTE* input, int length);
void EncryptString(BYTE* input);
//void EncryptStringA(string& input);
void DecryptString(BYTE* input);
//void DecryptStringA(string& input);

//BOOL DecryptFileLoadingData(CString SourceFile /*,int FirstKey*/, map<CString, WorldMapInfo> *pWorldMapData);
// void EncryptFile(CString SourceFile,CString TagerFile);
// void DecryptFile(CString SourceFile,CString TagerFile);


// extern "C" EXPORTED_SYMBOL void SayHello(const char *input);

// extern "C" EXPORTED_SYMBOL void PassPacket(const StrPacket* packet);

// extern "C" EXPORTED_SYMBOL void EncryptPacket(const char *aesKey,
//                                               const StrPacket *packet,
//                                               BYTE **data);

// extern "C" EXPORTED_SYMBOL void DecryptPacket(const char *aesKey,
//                                               const BYTE *data,
//                                               StrPacket *packet);

#endif