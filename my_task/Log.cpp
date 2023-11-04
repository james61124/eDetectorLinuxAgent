#include "Log.h"

#include <sstream>

void Log::logger(const std::string& level, const std::string& message) {

    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(12345);
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        std::cerr << "Error connecting to server." << std::endl;
        close(clientSocket);
        return;
    }

    std::string timestamp = GetTime();
    std::string MsgToSend = timestamp + " [" + level + "] " + message;

    if (send(clientSocket, MsgToSend.c_str(), MsgToSend.length(), 0) == -1) {
        std::cerr << "Error sending message." << std::endl;
    }

    close(clientSocket);
}

void Log::HandleLogClientConnection(int clientSocket) {

    char buffer[1024];
    int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
    if (bytesReceived > 0) {
        std::string message(buffer, bytesReceived);
        EnqueueMessage(message);
        //MsgQueue.push(message);
    }
    close(clientSocket);
}

void Log::WriteToLogFile() {
    std::string m_FilePath = "log.txt";
    
    while (true) {
        if (!MsgQueue.empty()) {
            std::ofstream outputFile(m_FilePath, std::ios::app);
            if (outputFile.is_open()) {
                std::string message;
                DequeueMessage(message);
                size_t pos = 0;
                while ((pos = message.find('\n', pos)) != std::string::npos) {
                    message.replace(pos, 1, "\\n");
                    pos += 2; // Move past the inserted "\\n"
                }
                //for (char c : message) {
                //    if (c == '\n') {
                //        outputFile << "\\n";
                //    }
                //    else {
                //        outputFile << c;
                //    }
                //}
                outputFile << message << std::endl;
            }
            else {
                std::cerr << "Error opening file for writing." << std::endl;
            }
            outputFile.close();
        }
    }
    
}

void Log::LogServer() {
    std::remove("log.txt");

    int listeningSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (listeningSocket == -1) {
        std::cerr << "Error creating listening socket." << std::endl;
        return;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(12345);
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (bind(listeningSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        std::cerr << "Error binding log server socket." << std::endl;
        close(listeningSocket);
        return;
    }

    if (listen(listeningSocket, SOMAXCONN) == -1) {
        std::cerr << "Error listening on log socket." << std::endl;
        close(listeningSocket);
        return;
    }

    std::thread LogThread([&]() { WriteToLogFile(); });
    LogThread.detach();

    
    while (true) {
        sockaddr_in clientAddr;
        socklen_t clientAddrSize = sizeof(clientAddr);
        int clientSocket = accept(listeningSocket, (sockaddr*)&clientAddr, &clientAddrSize);
        if (clientSocket > 0) {
            std::thread LogReceiveThread([&]() { HandleLogClientConnection(clientSocket); });
            LogReceiveThread.detach();
        }
        else {
            std::cerr << "Error accepting client connection." << std::endl;
        }
    }

    close(listeningSocket);
}



void Log::EnqueueMessage(const std::string& message) {
    std::lock_guard<std::mutex> lock(queueMutex);
    MsgQueue.push(message);
}

bool Log::DequeueMessage(std::string& message) {
    std::lock_guard<std::mutex> lock(queueMutex);
    if (!MsgQueue.empty()) {
        message = MsgQueue.front();
        MsgQueue.pop();
        return true;
    }
    return false;
}

std::string Log::GetTime() {
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
    std::time_t timeT = std::chrono::system_clock::to_time_t(now);
    std::tm localTm;

    localtime_r(&timeT, &localTm); 

    std::ostringstream formattedTime;
    formattedTime << std::put_time(&localTm, "%Y-%m-%d %H:%M:%S");

    return formattedTime.str();
}