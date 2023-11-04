#include <iostream>
#include <filesystem>
#include <fstream>
#include <chrono>
#include <ctime>
#include <string>

#include <iomanip>
#include <sys/stat.h>


namespace fs = std::filesystem;
using namespace std::chrono_literals;

typedef struct {
    bool isDirectory;
    long createTime;
    long writeTime;
    long accessTime;
    long EntryModifiedTime;
    int isDeleted;
    long long dataLen;
} FileAttributes;

class Explorer {
public:
    int m_progressIdx = 0;
    FileAttributes GetFileAttributes(const fs::path& filePath);
    void ListFilesRecursively(const fs::path& directoryPath, int depth, std::ofstream& outputFile);
    int GetExplorerInfo(std::string outputFilePath);
    
};