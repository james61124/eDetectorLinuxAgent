#include <vector>
#include <iostream>
#include <dirent.h>
#include <string>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <vector>
#include <unistd.h>
#include <ctime>
#include <limits.h>
#include <cstring>
#include <unordered_set>

typedef struct {
    int pid;
    std::string processName;
    long processCreateTime; // ProcessCreateTime in Unix timestamp (seconds)
    std::string dynamicCommand;
    std::string processPath; // Process executable path
    int parentPid; // Parent process PID
    std::string parentProcessName; // Parent process name
    std::string parentProcessPath; // Parent process path
} ProcessInfo;

class Scan {
public:
    std::unordered_set<int>process_id;
    std::vector<ProcessInfo>ProcessList;
    void ScanRunNowProcess();
    ProcessInfo* GetNewProcessInfo(std::string pid);

private:
    long jiffiesToUnixTimestamp(long jiffies);
    std::string getProcessPath(int pid);
};