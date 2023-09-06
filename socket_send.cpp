#include "socket_send.h"

SocketSend::SocketSend(Info* infoInstance) {
	info = infoInstance;
}

int SocketSend::SendDataToServer(char* Work, char* Mgs, int tcpSocket) {
	
	StrDataPacket GetServerMessage;
	strcpy(GetServerMessage.MAC, info->MAC);
	strcpy(GetServerMessage.IP, info->IP);
	strcpy(GetServerMessage.UUID, info->UUID);

	char WorkNew[24];
	strcpy(WorkNew, Work);
	WorkNew[strlen(Work)] = '\0';

	strcpy(GetServerMessage.DoWorking, WorkNew);
	memcpy(GetServerMessage.csMsg, Mgs, sizeof(GetServerMessage.csMsg));

	char* buff = (char*)&GetServerMessage;

	SetKeys(BIT128, AESKey);
	EncryptBuffer((BYTE*)buff, STRDATAPACKETSIZE);

	int ret = sendTCP(buff, STRDATAPACKETSIZE, tcpSocket);
	printf("Send Data Packet: %s\n", Work);

	if (ret > 0) {
		std::string Task(WorkNew);
		std::string Msg(Mgs);
		std::string LogMsg = "Send: " + Task + " " + Msg;
		log.logger("Info", LogMsg);
		return receiveTCP(tcpSocket);
	}
	else {
		std::string Task(WorkNew);
		std::string LogMsg = "Error Send: " + Task;
		log.logger("Error", LogMsg);
		return 0;
	}
	

	
	

	//delete[] Work;
	//delete[] Mgs;

	//return ret;
}

int SocketSend::SendMessageToServer(char* Work, char* Mgs) {
	Log log;
	StrPacket GetServerMessage;
	strcpy(GetServerMessage.MAC, info->MAC);
	strcpy(GetServerMessage.IP, info->IP);
	strcpy(GetServerMessage.UUID, info->UUID);

	char WorkNew[24];
	strcpy(WorkNew, Work);
	WorkNew[strlen(Work)] = '\0';
	

	strcpy(GetServerMessage.DoWorking, WorkNew);
	strcpy(GetServerMessage.csMsg, Mgs);

	char* buff = (char*)&GetServerMessage;

	SetKeys(BIT128, AESKey);
	EncryptBuffer((BYTE*)buff, STRPACKETSIZE);

	int ret = sendTCP(buff, STRPACKETSIZE, info->tcpSocket);


	printf("Send Message Packet: %s\n", Work);
	std::string Task(WorkNew);
	std::string Msg(Mgs);
	std::string LogMsg = "Send: " + Task + " " + Msg;
	log.logger("Info", LogMsg);

	delete[] Work;
	delete[] Mgs;
	return ret;
}

bool SocketSend::sendTCP(char* data, long len, int tcpSocket) {

	int ret = send(tcpSocket, data, len, 0);
	if (!ret) {
		Log log;
		std::string LogMsg = "Error Send data.";
		log.logger("Error", LogMsg);
	}
	else {
		// std::cout << "Data sent successfully." << std::endl;
	}

	return ret;
}

int SocketSend::receiveTCP(int tcpSocket) {
	
	while (true) {
		char buff[STRPACKETSIZE];
		int ret = recv(tcpSocket, buff, sizeof(buff), 0);

		SetKeys(BIT128, AESKey);
		DecryptBuffer((BYTE*)buff, STRPACKETSIZE);

		StrPacket* udata;
		udata = (StrPacket*)buff;

		printf("Receive: %s\n", udata->DoWorking);
		if (!strcmp(udata->DoWorking, "DataRight")) {
			return 1;
		}
		else {
			return 0;
		}
	}
	

	return 1;


}