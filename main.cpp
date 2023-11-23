#include <iostream>
#include <thread>
#include <sys/wait.h>

#include "my_task/info.h"
#include "my_task/socket_manager.h"
#include "my_task/socket_send.h"
#include "my_task/Log.h"

#include "my_task/task.h"





// bool IsProcessAlive(DWORD pid) {
// 	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
// 	if (hProcess == NULL) {
// 		// OpenProcess failed, process is likely not alive
// 		return false;
// 	}

// 	// Check if the process is still running
// 	DWORD exitCode;
// 	if (GetExitCodeProcess(hProcess, &exitCode) && exitCode == STILL_ACTIVE) {
// 		// Process is still active
// 		CloseHandle(hProcess);
// 		return true;
// 	}

// 	CloseHandle(hProcess);
// 	return false;
// }

// void CheckProcessStatus(Info* info) {
// 	Log log;
// 	while (true) {
// 		for (const auto& pair : info->processMap) {
// 			if (!IsProcessAlive(pair.second)) {
// 				if (info->processMap[pair.first] != 0) {
// 					string LogMsg = pair.first + " disconnected";
// 					log.logger("Error", LogMsg);
// 					printf("%s\n", LogMsg.c_str());
// 					info->processMap[pair.first] = 0;
// 				} 
// 				if (info->processMap["DetectProcess"] == 0 && info->DetectProcess == 1) {
// 					log.logger("Info", "DetectProcess connected");

// 					Tool tool;
// 					DWORD DetectProcessPid = 0;
// 					TCHAR* RunExeStr = new TCHAR[MAX_PATH];
// 					TCHAR* RunComStr = new TCHAR[512];
// 					GetModuleFileName(GetModuleHandle(NULL), RunExeStr, MAX_PATH);

// 					wstring filename = tool.GetFileName();
// 					TCHAR MyName[MAX_PATH];
// 					wcscpy_s(MyName, filename.c_str());

// 					TCHAR ServerIP[MAX_PATH];
// 					swprintf_s(ServerIP, MAX_PATH, L"%hs", info->ServerIP);

// 					swprintf_s(RunComStr, 512, L"\"%s\" %s %d DetectProcess", MyName, ServerIP, info->Port);
// 					wprintf(L"Run Process: %ls\n", RunComStr);
// 					RunProcessEx(RunExeStr, RunComStr, 1024, FALSE, FALSE, DetectProcessPid);
// 					info->processMap["DetectProcess"] = DetectProcessPid;
// 					log.logger("Debug", "DetectProcess enabled");
					
// 				}
				
// 			}
// 			else {
// 				string LogMsg = pair.first + " alive";
// 			}
// 		}
// 	}
// }

// nohup ./agent 192.168.200.163 1988 1989 &
void sigchld_handler(int signo) {
    (void)signo;
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

int main(int argc, char* argv[]) {

    
    // irfilelist();
    // Task task;
    // task.DetectProcess();

    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <serverIP> <port>" << std::endl;
        return 1;
    }

    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);

    std::string serverIP = argv[1];
    int port = std::stoi(argv[2]);
    std::string task = argv[3];

    Log log;
    Info* info = new Info();
    SocketSend* socketsend = new SocketSend(info);
    SocketManager socketManager(serverIP, port, info, socketsend);


    // enabled check process status thread
    // std::thread CheckStatusThread([&]() { CheckProcessStatus(info); });
    // CheckStatusThread.detach();

    pid_t childPid = fork();
    if (childPid == -1) std::cerr << "Fork failed." << std::endl;
    else if (childPid == 0) {
        log.LogServer();
        exit(EXIT_SUCCESS);
    }
    info->processMap["Log"] = childPid;

    childPid = fork();
    if (childPid == -1) std::cerr << "Fork failed." << std::endl;
    else if (childPid == 0) {
        socketManager.InfoInstance->tcpSocket = socketManager.task->CreateNewSocket();
        socketManager.getSystemInfo();
        socketManager.task->CheckConnect();
        exit(EXIT_SUCCESS);
    }
    info->processMap["CheckConnect"] = childPid;

    // handshake
    std::thread receiveThread([&]() { socketManager.receiveTCP(); });
    socketManager.HandleTaskToServer("GiveInfo");
    receiveThread.join();
}