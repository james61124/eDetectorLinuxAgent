#include "scan.h"

// Function to convert jiffies to Unix timestamp
long Scan::jiffiesToUnixTimestamp(long jiffies) {
    return jiffies / sysconf(_SC_CLK_TCK) + time(nullptr);
}

// Function to get process executable path
std::string Scan::getProcessPath(int pid) {
    char pathBuffer[PATH_MAX];
    std::string path = "/proc/" + std::to_string(pid) + "/exe";
    
    ssize_t len = readlink(path.c_str(), pathBuffer, sizeof(pathBuffer) - 1);
    if (len != -1) {
        pathBuffer[len] = '\0';
        return std::string(pathBuffer);
    } else {
        return "";
    }
}

void Scan::ScanRunNowProcess() {
    DIR *dir;
    struct dirent *entry;

    // Open the /proc directory
    dir = opendir("/proc");
    if (dir == NULL) {
        perror("opendir");
        return;
    }

    // Traverse the /proc directory
    while ((entry = readdir(dir)) != NULL) {
        // Ensure directory name is a number (PID)
        std::string dirName = entry->d_name;
        if (std::all_of(dirName.begin(), dirName.end(), ::isdigit)) {
            // Get process name
            std::ifstream commFile("/proc/" + dirName + "/comm");
            if (commFile) {
                std::string processName;
                getline(commFile, processName);

                // Get process start time (jiffies)
                std::ifstream statFile("/proc/" + dirName + "/stat");
                if (statFile) {
                    std::string statLine;
                    getline(statFile, statLine);
                    std::istringstream statStream(statLine);
                    std::vector<std::string> statTokens;
                    std::string token;

                    // Split the stat line into tokens
                    while (std::getline(statStream, token, ' ')) {
                        statTokens.push_back(token);
                    }

                    if (statTokens.size() >= 22) {
                        long processCreateTime = std::stol(statTokens[21]);

                        // Get process's DynamicCommand (command line arguments)
                        std::ifstream cmdLineFile("/proc/" + dirName + "/cmdline");
                        if (cmdLineFile) {
                            std::string dynamicCommand;
                            getline(cmdLineFile, dynamicCommand);

                            // Get process path
                            std::string processPath = getProcessPath(std::stoi(dirName));

                            // Get parent process's PID (fourth field)
                            int parentPid = std::stoi(statTokens[3]);

                            // Get parent process's name
                            std::ifstream parentCommFile("/proc/" + std::to_string(parentPid) + "/comm");
                            if (parentCommFile) {
                                std::string parentProcessName;
                                getline(parentCommFile, parentProcessName);

                                // Get parent process's path
                                std::string parentProcessPath = getProcessPath(parentPid);

                                // Convert to Unix timestamp
                                long unixTimestamp = jiffiesToUnixTimestamp(processCreateTime);

                                ProcessInfo process_info;
                                process_info.pid = std::stoi(dirName);
                                process_info.processName = processName;
                                process_info.processCreateTime = unixTimestamp;
                                process_info.dynamicCommand = dynamicCommand;
                                process_info.processPath = processPath;
                                process_info.parentPid = parentPid;
                                process_info.parentProcessName = parentProcessName;
                                process_info.parentProcessPath = parentProcessPath;

                                ProcessList.push_back(process_info);
                                process_id.insert(process_info.pid);

                                // std::cout << "PID: " << dirName << ", ProcessName: " << processName << ", ProcessCreateTime (Unix Timestamp): " << unixTimestamp << " seconds since Epoch, DynamicCommand: " << dynamicCommand << ", ProcessPath: " << processPath << ", ParentPID: " << parentPid << ", ParentProcessName: " << parentProcessName << ", ParentProcessPath: " << parentProcessPath << std::endl;
                            }
                        }
                    }
                }
            }
        }
    }

    closedir(dir);
}

ProcessInfo* Scan::GetNewProcessInfo(std::string pid) {
    ProcessInfo* process_info = nullptr;
    std::string dirName = pid;
    if (std::all_of(dirName.begin(), dirName.end(), ::isdigit)) {
        // Get process name
        std::ifstream commFile("/proc/" + dirName + "/comm");
        if (commFile) {
            std::string processName;
            getline(commFile, processName);

            // Get process start time (jiffies)
            std::ifstream statFile("/proc/" + dirName + "/stat");
            if (statFile) {
                std::string statLine;
                getline(statFile, statLine);
                std::istringstream statStream(statLine);
                std::vector<std::string> statTokens;
                std::string token;

                // Split the stat line into tokens
                while (std::getline(statStream, token, ' ')) {
                    statTokens.push_back(token);
                }

                if (statTokens.size() >= 22) {
                    long processCreateTime = std::stol(statTokens[21]);

                    // Get process's DynamicCommand (command line arguments)
                    std::ifstream cmdLineFile("/proc/" + dirName + "/cmdline");
                    if (cmdLineFile) {
                        std::string dynamicCommand;
                        getline(cmdLineFile, dynamicCommand);

                        // Get process path
                        std::string processPath = getProcessPath(std::stoi(dirName));

                        // Get parent process's PID (fourth field)
                        int parentPid = std::stoi(statTokens[3]);

                        // Get parent process's name
                        std::ifstream parentCommFile("/proc/" + std::to_string(parentPid) + "/comm");
                        if (parentCommFile) {
                            std::string parentProcessName;
                            getline(parentCommFile, parentProcessName);

                            // Get parent process's path
                            std::string parentProcessPath = getProcessPath(parentPid);

                            // Convert to Unix timestamp
                            long unixTimestamp = jiffiesToUnixTimestamp(processCreateTime);

                            process_info = new ProcessInfo;
                            process_info->pid = std::stoi(dirName);
                            process_info->processName = processName;
                            process_info->processCreateTime = unixTimestamp;
                            process_info->dynamicCommand = dynamicCommand;
                            process_info->processPath = processPath;
                            process_info->parentPid = parentPid;
                            process_info->parentProcessName = parentProcessName;
                            process_info->parentProcessPath = parentProcessPath;

                            ProcessList.push_back(*process_info);
                            process_id.insert(process_info->pid);

                            
                        }
                    }
                }
            }
        }
    }
    return process_info;
}