#pragma once
#include <iostream>
#include <cstring>
#include <thread>
#include <vector>
#include <mutex>
#include <fstream>
#include <queue>
#include <chrono>
#include <ctime>
#include <iomanip>

#include <sys/socket.h> 
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h> 

class Log {
public:
	std::queue<std::string>MsgQueue;
	std::mutex queueMutex;

	void logger(const std::string& level, const std::string& message);
	void HandleLogClientConnection(int clientSocket);
	void LogServer();
	void WriteToLogFile();
	void EnqueueMessage(const std::string& message);
	bool DequeueMessage(std::string& message);
	std::string GetTime();
};