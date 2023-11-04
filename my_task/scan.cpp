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

        ProcessInfo process_info;
        process_info.processName = "null";
        process_info.processCreateTime = 0;
        process_info.dynamicCommand = "null";
        process_info.processPath = "null";
        process_info.parentPid = 0;
        process_info.parentProcessName = "null";
        process_info.parentProcessPath = "null";



        // Ensure directory name is a number (PID)
        std::string dirName = entry->d_name;
        if (std::all_of(dirName.begin(), dirName.end(), ::isdigit)) {

            process_info.pid = std::stoi(dirName);

            // Get process name
            std::ifstream commFile("/proc/" + dirName + "/comm");
            if (commFile) {
                std::string processName;
                getline(commFile, processName);
                process_info.processName = processName;
                
            }

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
                    long unixTimestamp = jiffiesToUnixTimestamp(processCreateTime);
                    process_info.processCreateTime = unixTimestamp;
                }

                try {
                    // Get parent process's PID (fourth field)
                    int parentPid = std::stoi(statTokens[3]);

                    // Get parent process's path
                    std::string parentProcessPath = getProcessPath(parentPid);

                    process_info.parentProcessPath = parentProcessPath;
                    process_info.parentPid = parentPid;

                    // Get parent process's name
                    std::ifstream parentCommFile("/proc/" + std::to_string(parentPid) + "/comm");
                    if (parentCommFile) {
                        std::string parentProcessName;
                        getline(parentCommFile, parentProcessName);
                        process_info.parentProcessName = parentProcessName;
                    }

                } catch (const std::invalid_argument& e) {
                    std::cerr << "Invalid argument: " << e.what() << std::endl;
                }
            }

            // Get process's DynamicCommand (command line arguments)
            std::ifstream cmdLineFile("/proc/" + dirName + "/cmdline");
            if (cmdLineFile) {
                std::string dynamicCommand;
                std::string line;
                
                while (std::getline(cmdLineFile, line)) {
                    dynamicCommand += line;
                }

                if (dynamicCommand.empty()) {
                    dynamicCommand = "null";
                }
                
                process_info.dynamicCommand = dynamicCommand;
            }


            // Get process path
            std::string processPath = getProcessPath(std::stoi(dirName));

            if (processPath.empty()) {
                processPath = "[" + process_info.processName + "]";
            }

            process_info.processPath = processPath;

            
            ProcessList.push_back(process_info);
            process_id.insert(process_info.pid);

            // std::cout << "PID: " << dirName << ", ProcessName: " << processName << ", ProcessCreateTime (Unix Timestamp): " << unixTimestamp << " seconds since Epoch, DynamicCommand: " << dynamicCommand << ", ProcessPath: " << processPath << ", ParentPID: " << parentPid << ", ParentProcessName: " << parentProcessName << ", ParentProcessPath: " << parentProcessPath << std::endl;
                            
        }
    }

    closedir(dir);
}

ProcessInfo* Scan::GetNewProcessInfo(std::string pid) {
    ProcessInfo* process_info = nullptr;

    std::string dirName = pid;
    if (std::all_of(dirName.begin(), dirName.end(), ::isdigit)) {

        process_info = new ProcessInfo;

        process_info->pid = std::stoi(dirName);

        // Get process name
        std::ifstream commFile("/proc/" + dirName + "/comm");
        if (commFile) {
            std::string processName;
            getline(commFile, processName);
            process_info->processName = processName;
        }
        commFile.close(); 

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
                long unixTimestamp = jiffiesToUnixTimestamp(processCreateTime);
                process_info->processCreateTime = unixTimestamp;
            }

            try {
                // Get parent process's PID (fourth field)
                int parentPid = std::stoi(statTokens[3]);

                // Get parent process's path
                std::string parentProcessPath = getProcessPath(parentPid);

                process_info->parentProcessPath = parentProcessPath;
                process_info->parentPid = parentPid;

                // Get parent process's name
                std::ifstream parentCommFile("/proc/" + std::to_string(parentPid) + "/comm");
                if (parentCommFile) {
                    std::string parentProcessName;
                    getline(parentCommFile, parentProcessName);
                    process_info->parentProcessName = parentProcessName;
                }

            } catch (const std::invalid_argument& e) {
                std::cerr << "Invalid argument: " << e.what() << std::endl;
            }
        }
        statFile.close();

        // Get process's DynamicCommand (command line arguments)
        std::ifstream cmdLineFile("/proc/" + dirName + "/cmdline");
        if (cmdLineFile) {
            std::string dynamicCommand;
            getline(cmdLineFile, dynamicCommand);
            process_info->dynamicCommand = dynamicCommand;
        }
        cmdLineFile.close();

        // Get process path
        std::string processPath = getProcessPath(std::stoi(dirName));
        process_info->processPath = processPath;

        ProcessList.push_back(*process_info);
        process_id.insert(process_info->pid);


    }

    return process_info;
}