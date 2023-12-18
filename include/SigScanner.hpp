#pragma once

#include <windows.h>
#include <TlHelp32.h>
#include <utility>
#include <vector>
#include <sstream>
#include <string>
#include <Psapi.h>

std::vector<std::string> splitString(const std::string& str, char delim) {
    std::vector<std::string> retVal = {};
    std::istringstream split(str);
    for (std::string each; std::getline(split, each, delim); retVal.push_back(each));
    return retVal;
}

class SigScanner {
public:
    static uintptr_t scanMemoryPattern(const char* processName, const std::string& pattern, const char* moduleName = nullptr, int skips = 0x0) {
        HANDLE hProcess = getProcessHandle(processName);
        if (hProcess == nullptr)
            return 0;

        MODULEINFO moduleInfo;
        if (moduleName != nullptr) {
            moduleInfo = getModuleInfo(hProcess, moduleName);
        } else {
            HMODULE hModule = GetModuleHandle(nullptr);
            GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(moduleInfo));
        }

        auto startAddress = reinterpret_cast<uintptr_t>(moduleInfo.lpBaseOfDll);
        uintptr_t endAddress = startAddress + moduleInfo.SizeOfImage;

        CloseHandle(hProcess);

        return scan(nullptr, startAddress, endAddress, pattern, skips);
    }

    static MODULEINFO getModuleInfo(HANDLE hProcess, const char* moduleName) {
        MODULEINFO moduleInfo = { nullptr };
        HMODULE hModule = GetModuleHandle(moduleName);

        if (hModule != nullptr) {
            GetModuleInformation(hProcess, hModule, &moduleInfo, sizeof(moduleInfo));
        }

        return moduleInfo;
    }

private:
    static HANDLE getProcessHandle(const char* processName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        HANDLE hProcess = nullptr;

        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);

            if (Process32First(hSnapshot, &pe32)) {
                do {
                    if (std::string(pe32.szExeFile) == processName) {
                        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
                        break;
                    }
                } while (Process32Next(hSnapshot, &pe32));
            }

            CloseHandle(hSnapshot);
        }

        return hProcess;
    }

    static uintptr_t scan(HANDLE hProcess, uintptr_t start, uintptr_t end, const std::string& pattern, int skips) {
        int skipsUsed = skips;
        std::vector<std::string> vector = splitString(pattern, ' ');
        std::vector<int> signature = {};

        for (const auto& str : vector) {
            if (str == "??" || str == "?") {
                signature.push_back(-1);
            } else {
                signature.push_back((int)(std::stoul(str, nullptr, 16)));
            }
        }

        uintptr_t searchEnd = end - signature.size();

#define GET_BYTE(x) *((std::byte*)x)

        for (auto i = start; i < searchEnd; i++) {
            size_t j = 0;

            for (; j < signature.size(); j++) {
                if (i + j >= searchEnd)
                    return NULL;

                if (signature[j] != -1 && (int)GET_BYTE((i + j)) != signature[j])
                    break;
            }

            if (j >= signature.size()) {
                if (skipsUsed == 0) {
                    return i;
                }

                skipsUsed--;
            }
        }

        return 0;
    }
#undef GET_BYTE
};

