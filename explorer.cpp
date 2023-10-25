#include "explorer.h"

FileAttributes Explorer::GetFileAttributes(const fs::path& filePath) {
    FileAttributes attributes;
    try {
        const fs::file_status status = fs::status(filePath);
        attributes.isDirectory = fs::is_directory(status);

        struct stat fileStat;
        if (stat(filePath.c_str(), &fileStat) == 0) {

            // atime
            std::time_t accessTime = fileStat.st_atime;

            // mtime
            std::time_t modifyTime = fileStat.st_mtime;

            // ctime
            std::time_t changeTime = fileStat.st_ctime;

            attributes.createTime = 000;
            attributes.writeTime = 000;
            attributes.accessTime = accessTime;
            attributes.EntryModifiedTime = modifyTime;
            attributes.dataLen = (long)fileStat.st_size;
        }

        if (fs::exists(filePath)) attributes.isDeleted = 0;
        else attributes.isDeleted = 1;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    return attributes;
}

void Explorer::ListFilesRecursively(const fs::path& directoryPath, int depth, std::ofstream& outputFile) {
    if (depth > 10) {
        return;
    }

    try {
        int parent_progressIdx = m_progressIdx;   

        for (const auto& entry : fs::directory_iterator(directoryPath)) {
            if (entry.is_symlink()) {
                continue;
            }

            // "%u|%s|%llu|%d|%d|%s|%s|%s|%s|%llu|0\n",
            // m_progressIdx,
            // fn,
            // ParentId,
            // fr->IsDeleted(),
            // fr>IsDirectory(),
            // CreateTimeWstr,
            // WriteTimeWstr,
            // AccessTimeWstr,
            // EntryModifiedTimeWstr,
            // datalen

            m_progressIdx++;
            FileAttributes attributes = GetFileAttributes(entry.path());
            outputFile << entry.path().filename() << "|" << attributes.isDirectory << "|" << attributes.isDeleted << "|" << attributes.createTime << "|" << attributes.writeTime << "|" << attributes.accessTime << "|"
                                                            << attributes.EntryModifiedTime << "|" << attributes.dataLen << "|" << m_progressIdx << "|" << parent_progressIdx << std::endl;

                                     

            // outputFile << "Name: " << entry.path() << std::endl;
            // outputFile << "IsDirectory: " << attributes.isDirectory << std::endl;
            // outputFile << "isDeleted: " << attributes.isDeleted << std::endl;
            // outputFile << "CreateTime (Unix Timestamp): " << attributes.createTime << std::endl;
            // outputFile << "WriteTime (Unix Timestamp): " << attributes.writeTime << std::endl;
            // outputFile << "AccessTime (Unix Timestamp): " << attributes.accessTime << std::endl;
            // outputFile << "EntryModifiedTime (Unix Timestamp): " << attributes.EntryModifiedTime << std::endl;
            // outputFile << "dataLen: " << attributes.dataLen << std::endl;
            // outputFile << std::endl;
            
            
            if (attributes.isDirectory) {
                ListFilesRecursively(entry.path(), depth + 1, outputFile);
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}


int Explorer::GetExplorerInfo(std::string outputFilePath) {
    std::string rootPath = "/"; 

    fs::path rootDirectory(rootPath);

    std::ofstream outputFile(outputFilePath);

    if (outputFile.is_open()) {
        if (fs::is_directory(rootDirectory)) {
            ListFilesRecursively(rootDirectory, 0, outputFile);
        } else {
            std::cerr << "Error: The specified path is not a directory." << std::endl;
        }

        outputFile.close();
    } else {
        std::cerr << "Error: Unable to open the output file." << std::endl;
    }
}