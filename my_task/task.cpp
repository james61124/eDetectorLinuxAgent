#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <string>
#include <cstring>
#include <future>
#include <thread>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>



#include "task.h"

#define SCANFILE "scan.txt"
#define EXPLORERFILE "Explorer.txt"

Task::Task(Info* infoInstance, SocketSend* socketSendInstance) {

	// handshake
    functionMap["GiveInfo"] = std::bind(&Task::GiveInfo, this);
    // functionMap["GiveDriveInfo"] = std::bind(&Task::GiveDriveInfo, this);

	// functionMap["DetectProcess"] = std::bind(&Task::DetectProcess_, this);

    // // packet from server
    functionFromServerMap["OpenCheckthread"] = &Task::OpenCheckthread;
    functionFromServerMap["UpdateDetectMode"] = &Task::UpdateDetectMode;

	// // Scan
	functionFromServerMap["GetScan"] = &Task::GetScan;
	// functionMap["GiveProcessData"] = std::bind(&Task::GiveProcessData, this);
	

	// // Explorer
    functionFromServerMap["GetDrive"] = &Task::GetDrive; // ExplorerInfo_
	functionFromServerMap["ExplorerInfo"] = &Task::ExplorerInfo;

	// Collect
	functionFromServerMap["GetCollectInfo"] = &Task::GetCollectInfo;
	

	// Image
	functionFromServerMap["GetImage"] = &Task::GetImage;

	functionFromServerMap["TerminateAll"] = &Task::TerminateAll;

	

    info = infoInstance;
    socketsend = socketSendInstance;
}

// handshake
int Task::GiveInfo() {
    // getSystemInfo();

	// Netstat* netstat = new Netstat(info, socketsend);
	// int ret = netstat->scan_netstat();

	char* functionName = new char[24];
	strcpy(functionName, "GiveInfo");
	char* buffer = new char[STRINGMESSAGELEN];


	std::string SysInfo = "Unknown";
    #ifdef __x86_64__
        SysInfo = "x64";
    #elif __i386__
        SysInfo = "x86";
    #endif

	
	std::string OsStr = "";
	std::string cComputerName = "";
	std::string cUserName = "";
	unsigned long long BootTime = 0;
	long long m_DigitalSignatureHash = 0;

	std::ifstream os_release("/etc/os-release");
    std::string line;
    while (std::getline(os_release, line)) {
        if (line.find("PRETTY_NAME=") != std::string::npos) {
            size_t start = line.find("\"");
            size_t end = line.rfind("\"");
            if (start != std::string::npos && end != std::string::npos && start != end) {
                OsStr = line.substr(start + 1, end - start - 1);
            }
        }
    }

	struct utsname systemInfo;
    if (uname(&systemInfo) != -1) {
		cComputerName = systemInfo.nodename;
		cUserName = getenv("USER");
	} else {
		log.logger("Error", "failed to get system info");
	}

	// get boot time
	std::ifstream statFile("/proc/stat");
    while (std::getline(statFile, line)) {
        std::istringstream iss(line);
        std::string key;
        unsigned long long value;
        iss >> key;
        if (key == "btime") {
            if (iss >> value) {
				BootTime = value;
            } else {
				log.logger("Error", "Failed to parse btime value.");
            }
        }
    }
	
	// key
	std::string KeyNum = "";

	const char* filePath = "/var/lib/edetector/uuid";
	std::ifstream file(filePath);
    if (!file.is_open()) {
        KeyNum = "null";
    } else {
		std::string line;
		while (std::getline(file, line)) {
			KeyNum += line;
		}
		file.close();
	}
	strcpy(info->UUID, KeyNum.c_str());
	

	// file version
	char* FileVersion = new char[64];
	strcpy(FileVersion, "1.0.0");
	snprintf(buffer, STRINGMESSAGELEN, "%s|%s|%s|%s|%s,%d,%d|%lld|%s|%llu", SysInfo.c_str(), OsStr.c_str(), cComputerName.c_str(), cUserName.c_str(), FileVersion, info->Port, info->DetectPort, BootTime, KeyNum.c_str(), m_DigitalSignatureHash);
    
    return socketsend->SendMessageToServer(functionName, buffer);
}
int Task::OpenCheckthread(StrPacket* udata) {

	const char* path = "/var/lib/edetector";
	const char* filePath = "/var/lib/edetector/uuid";
	struct stat path_info;
    if (stat(path, &path_info) != 0) {
        if (mkdir(path, 0755) != 0) {
            log.logger("Error", "can't create edetector folder");
            return 0;
        }
    } else if (!(path_info.st_mode & S_IFDIR)) {
        log.logger("Error", "edetector exists, but it is not a folder");
        return 0;
    }
	
	// if (strcmp(udata->csMsg, "null")) {
	//  	strcpy(info->UUID, udata->csMsg);

	// 	std::ofstream file(filePath);
	// 	if (!file.is_open()) {
	// 		log.logger("Error", "can't open uuid file");
	// 		return 0;
	// 	}
	// 	file << udata->csMsg;
	// 	file.close();

	// }
	

	// std::thread CheckConnectThread([&]() { CheckConnect(); });
	// CheckConnectThread.detach();

	return GiveDetectInfoFirst();

}
int Task::GiveDetectInfoFirst() {
	char* buff = new char[STRINGMESSAGELEN];
	char* functionName = new char[24];
	strcpy(functionName, "GiveDetectInfoFirst");
	snprintf(buff, STRINGMESSAGELEN, "%d|%d", info->DetectProcess, info->DetectNetwork);
	return socketsend->SendMessageToServer(functionName, buff);
}
int Task::UpdateDetectMode(StrPacket* udata) {

	std::vector<std::string>DetectMode = tool.SplitMsg(udata->csMsg);
	for (int i = 0; i < DetectMode.size(); i++) {
		if (i == 0) info->DetectProcess = DetectMode[i][0] - '0';
		else if (i == 1) info->DetectNetwork = DetectMode[i][0] - '0';
		else printf("UpdateDetectMode parse failed\n");
	}

	if (info->DetectProcess) {
		int DetectProcessPid = 0;

		pid_t childPid = fork();
		if (childPid == -1) {
			log.logger("Error", "failed to create DetectProcess process");
		}
		else if (childPid == 0) {
			info->tcpSocket = CreateNewSocket();
			DetectProcess();
			exit(EXIT_SUCCESS);
		}

		info->processMap["DetectProcess"] = childPid;
		log.logger("Debug", "DetectProcess enabled");

		// DetectProcess();
	}
	else {
		auto it = info->processMap.find("DetectProcess");
		if (it != info->processMap.end() && it->second != 0 ) {
			if (kill(it->second, SIGKILL) == 0) {
				log.logger("Info", "DetectProcess has been terminated");
				it->second = 0;
			} else {
				log.logger("Error", "Failed to terminate DetectProcess");
			}
		}
	}

	if (info->DetectNetwork) {
		int DetectNetworkPid = 0;
		// run detect network

		pid_t childPid = fork();
		if (childPid == -1) {
			log.logger("Error", "failed to create DetectNetwork process");
		}
		else if (childPid == 0) {
			info->tcpSocket = CreateNewSocket();
			DetectNetwork();
			exit(EXIT_SUCCESS);
		}

		info->processMap["DetectNetwork"] = childPid;
		log.logger("Debug", "DetectNetwork enabled");
	}
	else {
		auto it = info->processMap.find("DetectNetwork");
		if (it != info->processMap.end() && it->second != 0) {
			if (kill(it->second, SIGKILL) == 0) {
				log.logger("Info", "DetectNetwork has been terminated");
				it->second = 0;
			} else {
				log.logger("Error", "Failed to terminate DetectNetwork");
			}
		}
	}

	return GiveDetectInfo();

}
int Task::GiveDetectInfo() {
	char* buff = new char[STRINGMESSAGELEN];
	char* functionName = new char[24];
	strcpy(functionName, "GiveDetectInfo");
	snprintf(buff, STRINGMESSAGELEN, "%d|%d", info->DetectProcess, info->DetectNetwork);
	int ret = socketsend->SendMessageToServer(functionName, buff);

	// network
	//DWORD MyPid = GetCurrentProcessId();
	//DetectNewNetwork(MyPid);

	// test
	// GiveProcessData();

	// Netstat* netstat = new Netstat(info, socketsend);
	// netstat->scan_netstat();
	// my_ps();


	return ret;
}
int Task::CheckConnect() {

    while(true){
		char* null = new char[1];
		strcpy(null, "");
		if (!SendMessagePacketToServer("CheckConnect", null)) {
			printf("CheckConnect sent failed\n");
		}
		std::this_thread::sleep_for(std::chrono::seconds(30));
    }

    // to do
    // check kill time

    return 0;
}


void Task::DetectProcess() {

	remove("/tmp/edetector");

	pid_t childPid = fork();
	if (childPid == -1) {
		log.logger("Error", "failed to create DetectProcess process");
	}
	else if (childPid == 0) {
		info->tcpSocket = CreateNewSocket();
		detect_ps();
		exit(EXIT_SUCCESS);
	}

	int sockfd, client_sockfd;
    struct sockaddr_un server_addr, client_addr;
    char buffer[DATASTRINGMESSAGELEN];
    
    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return;
    }

    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, "/tmp/edetector", sizeof(server_addr.sun_path));

    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind");
        return;
    }

    if (listen(sockfd, 1) == -1) {
        perror("listen");
        return;
    }

    socklen_t client_len = sizeof(client_addr);
    client_sockfd = accept(sockfd, (struct sockaddr*)&client_addr, &client_len);

    if (client_sockfd == -1) {
        perror("accept");
        return;
    }

	while(true) {
		int bytesRead = read(client_sockfd, buffer, sizeof(buffer));
		if (bytesRead > 0) {
			buffer[bytesRead] = '\0';
			// printf("%s\n", buffer);
			SendDataPacketToServer("GiveDetectProcess", buffer);

			const char* response = "DataRight";
			write(client_sockfd, response, strlen(response));
		}
	}

    close(client_sockfd);
    close(sockfd);



	// Scan* scan = new Scan();
	// // scan->ScanRunNowProcess();

	// while(true) {
	// 	DIR *dir;
	// 	struct dirent *entry;

	// 	// Open the /proc directory
	// 	// Traverse the /proc directory
	// 	while(true) {
	// 		dir = opendir("/proc");
	// 		if (dir == NULL) {
	// 			perror("opendir");
	// 			return;
	// 		}

	// 		try { // has to deal with stoi issue
	// 			while ((entry = readdir(dir)) != NULL) {
	// 				// Ensure directory name is a number (PID)
	// 				std::string dirName = entry->d_name;
	// 				if (std::all_of(dirName.begin(), dirName.end(), ::isdigit)) {
	// 					auto it = scan->process_id.find(std::stoi(dirName));		
	// 					if (it == scan->process_id.end()) {
	// 						ProcessInfo* process_info = scan->GetNewProcessInfo(dirName);
	// 						if(process_info!=nullptr) {
	// 							char* buff = new char[DATASTRINGMESSAGELEN];
	// 							sprintf(buff, "%s|%ld|%s|0|%s|%d|%s|%s|0|%d|0,0|0|0,0|0,0|null|null",
	// 									process_info->processName.c_str(), 
	// 									process_info->processCreateTime, 
	// 									process_info->dynamicCommand.c_str(), 
	// 									process_info->processPath.c_str(), 
	// 									process_info->parentPid, 
	// 									process_info->parentProcessName.c_str(), 
	// 									process_info->parentProcessPath.c_str(),
	// 									process_info->pid);
	// 							SendDataPacketToServer("GiveDetectProcess", buff);
	// 						}
							
	// 					}
	// 				}
					
	// 			}
				
	// 		} catch (const std::exception& e) {
	// 			std::cerr << "Exception caught: " << e.what() << std::endl;
	// 		}

	// 		closedir(dir);

			
	// 	}
		
	// }
}

void Task::DetectNetwork() {
	Netstat* netstat = new Netstat(info, socketsend);
	netstat->my_netstat();
}

int Task::GetScan(StrPacket* udata) {

	pid_t childPid = fork();
    if (childPid == -1) {
		log.logger("Error", "failed to create scan process");
	}
    else if (childPid == 0) {
		info->tcpSocket = CreateNewSocket();
        GiveProcessData();
        exit(EXIT_SUCCESS);
    }

	info->processMap["Scan"] = childPid;

	// GiveProcessData();
}

bool Task::isAutorunProcess(pid_t processId) {
    // Convert process ID to string
    std::string pidString = std::to_string(processId);

    // Check if the process ID is present in /proc
    std::ifstream procFile("/proc/" + pidString + "/cmdline");
    if (!procFile.is_open()) {
        std::cerr << "Error opening /proc/" << pidString << "/cmdline." << std::endl;
        return false;
    }

    // Read the cmdline file to get the command line of the process
    std::string cmdline;
    std::getline(procFile, cmdline);

    // Check if the command line contains an indicator of autorun
    bool isAutorun = (cmdline.find("/etc/init.d/") != std::string::npos ||
                      cmdline.find("/etc/systemd/system/") != std::string::npos ||
                      cmdline.find("/etc/rc.d/") != std::string::npos);

    return isAutorun;
}

int Task::GiveProcessData() {

	// printf("scan network\n");

	Netstat* netstat = new Netstat(info, socketsend);
	int ret = netstat->scan_netstat();

	// printf("scan run now process\n");
	Scan* scan = new Scan();
	try { // has to deal with stoi issue
		scan->ScanRunNowProcess();
	} catch (const std::exception& e) {
		// std::cerr << "Exception caught: " << e.what() << std::endl;
	}
	// printf("scan run now process end\n");

	std::remove(SCANFILE);
	// std::remove("scan.zip");
	std::remove("scan.tar.gz");

	std::ofstream file(SCANFILE, std::ios::out | std::ios::app);
    if (!file) {
        log.logger("Error", "Can't open scan file");
        return 0;
    }

	// vmtoolsd.exe|
	// 1691580721|
	// "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"|
	// 80abd555c1869baaff2d8a8d535ce07e|
	// C:\Program Files\VMware\VMware Tools\vmtoolsd.exe|
	// 656|
	// null|
	// null|
	// Mware, Inc.|
	// 2992|
	// 0,0|
	// 0|
	// 1,0|
	// 0,0|
	// C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.23070.1004-0\MpOav.dll:1,26791ea393ffed815c9332f05c025721;|
	// NlsAnsiCodePage:0x0000FFFD0000FDE9 -> 0x0000003F000003B6;|
	// 10.0.2.15,51858,204.79.197.200,443,CLOSE_WAIT>1691129938

	for(int i=0;i<scan->ProcessList.size();i++) {
		char* progress = new char[DATASTRINGMESSAGELEN];
		sprintf(progress, "%d/%d", i, scan->ProcessList.size());
		int ret = SendDataPacketToServer("GiveScanProgress", progress);
		
		scan->ProcessList[i].network = "null";

		for(int j=0;j<netstat->net_info.size();j++){
			if(std::stoi(netstat->net_info[j].process_name) == scan->ProcessList[i].pid) {

				std::string network_state = "";
				switch (netstat->net_info[j].state) {
					case 1: network_state = "TCP_ESTABLISHED"; break;
					case 2: network_state = "TCP_SYN_SENT"; break;
					case 3: network_state = "TCP_SYN_RECV"; break;
					case 4: network_state = "TCP_FIN_WAIT1"; break;
					case 5: network_state = "TCP_FIN_WAIT2"; break;
					case 6: network_state = "TCP_TIME_WAIT"; break;
					case 7: network_state = "TCP_CLOSE"; break;
					case 8: network_state = "TCP_CLOSE_WAIT"; break;
					case 9: network_state = "TCP_LAST_ACK"; break;
					case 10: network_state = "TCP_LISTEN"; break;
					case 11: network_state = "TCP_CLOSING"; break;
					default: network_state = "Unknown State"; break;
				}

				scan->ProcessList[i].network = info->IP;
				scan->ProcessList[i].network += ",";
				scan->ProcessList[i].network += netstat->net_info[j].local_port;
				scan->ProcessList[i].network += ",";
				scan->ProcessList[i].network += netstat->net_info[j].foreign_address;
				scan->ProcessList[i].network += ",";
				scan->ProcessList[i].network += netstat->net_info[j].foreign_port;
				scan->ProcessList[i].network += ",";
				scan->ProcessList[i].network += network_state;
				scan->ProcessList[i].network += ">";
				scan->ProcessList[i].network += netstat->net_info[j].socket_time;
				scan->ProcessList[i].network += ";";
			}
		}

		int isAutoRun = 0;
		if(isAutorunProcess(scan->ProcessList[i].pid)) isAutoRun = 1;

		char* buff = new char[DATASTRINGMESSAGELEN];
		// %s|%ld|%s|ProcessMD5|%s|%d|%s|%s|DigitalSign|%ld|InjectionPE, InjectionOther|Injected|Service, AutoRun|HideProcess, HideAttribute|ImportOtherDLL|Hook|ProcessConnectIP
		sprintf(buff, "%s|%ld|%s|0|%s|%d|%s|%s|0|%d|0,0|0|0,%d|0,0|null|null|%s",
				scan->ProcessList[i].processName.c_str(), 
				scan->ProcessList[i].processCreateTime, 
				scan->ProcessList[i].dynamicCommand, 
				scan->ProcessList[i].processPath.c_str(), 
				scan->ProcessList[i].parentPid, 
				scan->ProcessList[i].parentProcessName.c_str(), 
				scan->ProcessList[i].parentProcessPath.c_str(),
				scan->ProcessList[i].pid,
				isAutoRun,
				scan->ProcessList[i].network.c_str());
		printf("%s\n", scan->ProcessList[i].dynamicCommand);
		file << buff << '\n';
		delete[] buff; 

	}

    file.close();

	
	// my_ps();

	std::string scan_file(SCANFILE);
	// std::string compress_command = "zip scan.zip " + scan_file;
	std::string compress_command = "tar -czvf scan.tar.gz " + scan_file;
    int compress_result = system(compress_command.c_str());
    if (compress_result != 0) {
        log.logger("Error", "Can't compress scan file");
        return 0;
    }

	if(!SendZipFileToServer("Scan", "scan.tar.gz")) log.logger("Error", "failed to send scan tar file.");

    
	
}


int Task::GetDrive(StrPacket* udata) {
	const char* message = "Linux-EXT32,HDD|";
	char* buff = new char[STRINGMESSAGELEN];
	strcpy(buff, message);
	
	return SendMessagePacketToServer("GiveDriveInfo", buff);
}
int Task::ExplorerInfo(StrPacket* udata) {
	pid_t childPid = fork();
    if (childPid == -1) {
		log.logger("Error", "failed to create explorer process");
	}
    else if (childPid == 0) {
		info->tcpSocket = CreateNewSocket();
        GiveExplorerData();
        exit(EXIT_SUCCESS);
    }

	info->processMap["Explorer"] = childPid;
}
int Task::GiveExplorerData() {
	std::remove(EXPLORERFILE);
	// std::remove("explorer.zip");
	std::remove("explorer.tar.gz");

	char* TmpBuffer = new char[DATASTRINGMESSAGELEN];
	sprintf(TmpBuffer, "%s|%s", "Linux", "EXT32");
	int ret = SendDataPacketToServer("Explorer", TmpBuffer);

	char* progress = new char[DATASTRINGMESSAGELEN];
	sprintf(progress, "%d/%d", 100000, 300000);
	SendDataPacketToServer("GiveExplorerProgress", progress);

	

	Explorer* explorer = new Explorer();
	explorer->GetExplorerInfo("Explorer.txt");


	std::string explorer_file(EXPLORERFILE);
	// std::string compress_command = "zip explorer.zip " + explorer_file;
	std::string compress_command = "tar -czvf explorer.tar.gz " + explorer_file;
    int compress_result = system(compress_command.c_str());
    if (compress_result != 0) {
        log.logger("Error", "Can't compress explorer file");
        return 0;
    }

	char* progress_end = new char[DATASTRINGMESSAGELEN];
	sprintf(progress_end, "%d/%d", 300000, 300000);
	SendDataPacketToServer("GiveExplorerProgress", progress_end);

	if(!SendZipFileToServer("Explorer", "explorer.tar.gz")) log.logger("Error", "failed to send explorer tar file.");

	return ret;


}

int Task::GetCollectInfo(StrPacket* udata) {
	pid_t childPid = fork();
    if (childPid == -1) {
		log.logger("Error", "failed to create Collect process");
	}
    else if (childPid == 0) {
        exit(EXIT_SUCCESS);
    }
}


int Task::GetImage(StrPacket* udata) {
	pid_t childPid = fork();
    if (childPid == -1) {
		log.logger("Error", "failed to create image process");
	}
    else if (childPid == 0) {
		info->tcpSocket = CreateNewSocket();
        SearchImageFile();
        exit(EXIT_SUCCESS);
    }
	info->processMap["Image"] = childPid;
}
int Task::SearchImageFile() {
	irfilelist();
	if(!SendZipFileToServer("Image", "IR_list.tar.gz")) log.logger("Error", "failed to send image zip file.");
	return 1;
}

int Task::TerminateAll(StrPacket* udata) {
	pid_t childPid = fork();
    if (childPid == -1) {
		log.logger("Error", "failed to create terminate process");
	}
    else if (childPid == 0) {
		info->tcpSocket = CreateNewSocket();
        TerminateAllTask();
        exit(EXIT_SUCCESS);
    }
	info->processMap["TerminateAll"] = childPid;
}
int Task::TerminateAllTask() {
	auto it = info->processMap.find("DetectProcess");
	for (auto entry : info->processMap) {
		if (entry.first != "Log" && entry.first != "CheckConnect" && entry.first != "DetectProcess" && entry.first != "DetectNetwork") {
			if (kill(entry.second, SIGKILL) == 0) {
				std::string Msg = entry.first;
				std::string LogMsg = Msg + " has been terminated";
				log.logger("Info", LogMsg);
				entry.second = 0;
			} else {
				std::string Msg = entry.first;
				std::string LogMsg = "Failed to terminate " + Msg;
				log.logger("Debug", LogMsg);
			}
		}
	}

	char* null = new char[1];
	strcpy(null, "");
	SendDataPacketToServer("FinishTerminate", null);
	
	return 1;
}

int Task::SendZipFileToServer(const char* feature, const char* zipFileName) {
    int m_File = open(zipFileName, O_RDONLY);
    if (m_File != -1) {
        struct stat fileStat;
        if (fstat(m_File, &fileStat) == 0) {
            off_t m_Filesize = fileStat.st_size;
            int Sendret;
            char InfoStr[MAX_PATH_EX];
            snprintf(InfoStr, MAX_PATH_EX, "%lu", m_Filesize);
            char TmpBuffer[DATASTRINGMESSAGELEN];
            memset(TmpBuffer, '\x0', DATASTRINGMESSAGELEN);
            memcpy(TmpBuffer, InfoStr, strlen(InfoStr));

			if(!strcmp(feature, "Scan")) Sendret = SendDataPacketToServer("GiveScanInfo", TmpBuffer);
			else if(!strcmp(feature, "Image")) Sendret = SendDataPacketToServer("GiveImageInfo", TmpBuffer);
			else if(!strcmp(feature, "Explorer")) {
				Sendret = SendDataPacketToServer("GiveExplorerInfo", TmpBuffer);
			}
			else {
				log.logger("Error", "SendZipFileToServer feature not found.");
				return 0;
			}
            // Sendret = GiveScanInfo(TmpBuffer, tcpSocket);

            if (Sendret > 0) {
                off_t readsize;
                char buffer[m_Filesize];
                ssize_t bytesRead = read(m_File, buffer, m_Filesize);
                if (bytesRead > 0) {
                    off_t tmplen = m_Filesize;
                    for (off_t i = 0; i < m_Filesize; i += DATASTRINGMESSAGELEN) {
                        memset(TmpBuffer, '\x00', DATASTRINGMESSAGELEN);
                        if (tmplen < DATASTRINGMESSAGELEN) {
                            memcpy(TmpBuffer, buffer + i, tmplen);
                        } else {
                            memcpy(TmpBuffer, buffer + i, DATASTRINGMESSAGELEN);
                            tmplen -= DATASTRINGMESSAGELEN;
                        }

						if(!strcmp(feature, "Scan")) Sendret = SendDataPacketToServer("GiveScan", TmpBuffer);
						else if(!strcmp(feature, "Image")) Sendret = SendDataPacketToServer("GiveImage", TmpBuffer);
						else if(!strcmp(feature, "Explorer")) Sendret = SendDataPacketToServer("GiveExplorerData", TmpBuffer);
						else {
							log.logger("Error", "SendZipFileToServer feature not found.");
							return 0;
						}
						// Sendret = GiveScan(TmpBuffer, tcpSocket);

                        if (Sendret == 0 || Sendret == -1) break;
                    }
                }
                memset(TmpBuffer, '\x00', DATASTRINGMESSAGELEN);
            }
            if (Sendret > 0) {
                memset(TmpBuffer, '\x00', DATASTRINGMESSAGELEN);

				if(!strcmp(feature, "Scan")) Sendret = SendDataPacketToServer("GiveScanEnd", TmpBuffer);
				else if(!strcmp(feature, "Image")) Sendret = SendDataPacketToServer("GiveImageEnd", TmpBuffer);
				else if(!strcmp(feature, "Explorer")) Sendret = SendDataPacketToServer("GiveExplorerEnd", TmpBuffer);
				else {
					log.logger("Error", "SendZipFileToServer feature not found.");
					return 0;
				}
				// Sendret = GiveScanEnd(TmpBuffer, tcpSocket);

                close(m_File);
            }
        }
    } else {
		log.logger("Error", "zip file not exists.");
		return 0;
    }
	return 1;
}

int Task::SendDataPacketToServer(const char* function, char* buff) {
	char* functionName = new char[24];
	strcpy(functionName, function);
	return socketsend->SendDataToServer(functionName, buff);
}

int Task::SendMessagePacketToServer(const char* function, char* buff) {
	char* functionName = new char[24];
	strcpy(functionName, function);
	return socketsend->SendMessageToServer(functionName, buff);
}

int Task::CreateNewSocket() {

	int tcpSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (tcpSocket == -1) {
        perror("Error creating TCP socket");
        return false;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(info->Port);
    serverAddr.sin_addr.s_addr = inet_addr(info->ServerIP);

    while (connect(tcpSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

	return tcpSocket;
}
