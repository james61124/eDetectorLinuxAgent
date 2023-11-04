#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <string>
#include <cstring>
#include <future>
#include <thread>

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

    info = infoInstance;
    socketsend = socketSendInstance;
}

// handshake
int Task::GiveInfo() {
    // getSystemInfo();
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

		info->processMap["DetectNetwork"] = DetectNetworkPid;
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
	Scan* scan = new Scan();
	// scan->ScanRunNowProcess();

	while(true) {
		DIR *dir;
		struct dirent *entry;

		// Open the /proc directory
		// Traverse the /proc directory
		while(true) {
			dir = opendir("/proc");
			if (dir == NULL) {
				perror("opendir");
				return;
			}

			try { // has to deal with stoi issue
				while ((entry = readdir(dir)) != NULL) {
					// Ensure directory name is a number (PID)
					std::string dirName = entry->d_name;
					if (std::all_of(dirName.begin(), dirName.end(), ::isdigit)) {
						auto it = scan->process_id.find(std::stoi(dirName));		
						if (it == scan->process_id.end()) {
							ProcessInfo* process_info = scan->GetNewProcessInfo(dirName);
							if(process_info!=nullptr) {
								char* buff = new char[DATASTRINGMESSAGELEN];
								sprintf(buff, "%s|%ld|%s|0|%s|%d|%s|%s|0|%d|0,0|0|0,0|0,0|null|null",
										process_info->processName.c_str(), 
										process_info->processCreateTime, 
										process_info->dynamicCommand.c_str(), 
										process_info->processPath.c_str(), 
										process_info->parentPid, 
										process_info->parentProcessName.c_str(), 
										process_info->parentProcessPath.c_str(),
										process_info->pid);
								SendDataPacketToServer("GiveDetectProcess", buff);
							}
							
						}
					}
					
				}
				
			} catch (const std::exception& e) {
				std::cerr << "Exception caught: " << e.what() << std::endl;
			}

			closedir(dir);

			
		}
		
	}
}

void Task::DetectNetwork() {
	Netstat* netstat = new Netstat(info, socketsend);
	netstat->my_netstat();
}

int Task::GetScan(StrPacket* udata) {
	// pid_t childPid = fork();
    // if (childPid == -1) {
	// 	log.logger("Error", "failed to create scan process");
	// }
    // else if (childPid == 0) {
	// 	info->tcpSocket = CreateNewSocket();
    //     GiveProcessData();
    //     exit(EXIT_SUCCESS);
    // }

	GiveProcessData();
}

int Task::GiveProcessData() {
	Scan* scan = new Scan();
	try { // has to deal with stoi issue
		scan->ScanRunNowProcess();
	} catch (const std::exception& e) {
		// std::cerr << "Exception caught: " << e.what() << std::endl;
	}

	std::remove(SCANFILE);
	std::remove("scan.zip");

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

		char* buff = new char[DATASTRINGMESSAGELEN];
		// %s|%ld|%s|ProcessMD5|%s|%d|%s|%s|DigitalSign|%ld|InjectionPE, InjectionOther|Injected|Service, AutoRun|HideProcess, HideAttribute|ImportOtherDLL|Hook|ProcessConnectIP
		sprintf(buff, "%s|%ld|%s|0|%s|%d|%s|%s|0|%d|0,0|0|0,0|0,0|null|null|null",
				scan->ProcessList[i].processName.c_str(), 
				scan->ProcessList[i].processCreateTime, 
				scan->ProcessList[i].dynamicCommand.c_str(), 
				scan->ProcessList[i].processPath.c_str(), 
				scan->ProcessList[i].parentPid, 
				scan->ProcessList[i].parentProcessName.c_str(), 
				scan->ProcessList[i].parentProcessPath.c_str(),
				scan->ProcessList[i].pid);
		file << buff << '\n';
		delete[] buff; 

	}

    file.close();

	std::string scan_file(SCANFILE);
	std::string compress_command = "zip scan.zip " + scan_file;
    int compress_result = system(compress_command.c_str());
    if (compress_result != 0) {
        log.logger("Error", "Can't compress scan file");
        return 0;
    }

	if(!SendZipFileToServer("Scan", "scan.zip")) log.logger("Error", "failed to send scan zip file.");

    
	
}


int Task::GetDrive(StrPacket* udata) {
	const char* message = "Linux-EXT32,HDD|";
	char* buff = new char[STRINGMESSAGELEN];
	strcpy(buff, message);
	
	return SendDataPacketToServer("GiveDriveInfo", buff);
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
}
int Task::GiveExplorerData() {
	std::remove(EXPLORERFILE);
	std::remove("explorer.zip");

	char* TmpBuffer = new char[DATASTRINGMESSAGELEN];
	sprintf(TmpBuffer, "%s|%s", "Linux", "EXT32");
	int ret = SendDataPacketToServer("Explorer", TmpBuffer);

	char* progress = new char[DATASTRINGMESSAGELEN];
	sprintf(progress, "%d/%d", 100000, 300000);
	SendDataPacketToServer("GiveExplorerProgress", progress);

	

	Explorer* explorer = new Explorer();
	explorer->GetExplorerInfo("Explorer.txt");


	std::string explorer_file(EXPLORERFILE);
	std::string compress_command = "zip explorer.zip " + explorer_file;
    int compress_result = system(compress_command.c_str());
    if (compress_result != 0) {
        log.logger("Error", "Can't compress explorer file");
        return 0;
    }

	char* progress_end = new char[DATASTRINGMESSAGELEN];
	sprintf(progress_end, "%d/%d", 300000, 300000);
	SendDataPacketToServer("GiveExplorerProgress", progress_end);

	if(!SendZipFileToServer("Explorer", "explorer.zip")) log.logger("Error", "failed to send explorer zip file.");

	return ret;


}

int Task::GetCollectInfo(StrPacket* udata) {
	pid_t childPid = fork();
    if (childPid == -1) {
		log.logger("Error", "failed to create Collect process");
	}
    else if (childPid == 0) {
		info->tcpSocket = CreateNewSocket();
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
}
int Task::SearchImageFile() {
	// const char* file_names[] = {
    //     "/home/*/.bash_history",
    //     "/root/.bash_history",
    //     "/var/log/",
    //     "/proc/version",
    //     "/etc/*-release",
    //     "/etc/hostname",
    //     "/etc/passwd",
    //     "/etc/hosts",
    //     "/etc/sudoers",
    //     "/etc/ssh/sshd_config",
    //     "/etc/shells",
    //     "/etc/cron.",
    //     "/etc/crontab",
    //     "/var/spool/cron/crontabs",
    //     "/etc/anacrontab",
    //     "/var/spool/anacron",
    //     "/proc/net/arp",
    //     "/proc/net/route",
    //     "/etc/resolv.conf",
    //     "/proc/mounts",
    //     "/etc/exports",
    //     "/etc/fstab"
    // };

    // int total_length = 0;
    // for (int i = 0; i < sizeof(file_names) / sizeof(file_names[0]); i++) {
    //     total_length += snprintf(NULL, 0, "%s ", file_names[i]);
    // }

    // char* files_to_zip = (char*)malloc(total_length + 1);
    // int offset = 0;
    // for (int i = 0; i < sizeof(file_names) / sizeof(file_names[0]); i++) {
    //     offset += snprintf(files_to_zip + offset, total_length - offset + 1, "%s ", file_names[i]);
    // }

    // files_to_zip[total_length - 1] = '\0';
    // char zip_command[1024];
    // snprintf(zip_command, sizeof(zip_command), "zip image.zip %s", files_to_zip);
    // int result = system(zip_command);

    // if (result) {
	// 	log.logger("Error", "failed to zip image file.");
	// 	return 0;
	// }
    // free(files_to_zip);

	irfilelist();
	if(!SendZipFileToServer("Image", "IR_list.tar.gz")) log.logger("Error", "failed to send image zip file.");

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
