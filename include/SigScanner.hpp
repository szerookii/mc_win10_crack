#pragma once

#include <windows.h>
#include <TlHelp32.h>
#include <vector>
#include <sstream>
#include <string>
#include <Psapi.h>

#include <obfuscate.hpp>
#include <lazy_importer.hpp>

class SigScanner {
public:
    static uintptr_t scanMemoryPattern(const char* processName, const char* pattern, const char* moduleName = nullptr, int skips = 0x0) {
        HANDLE hSnapshot = LI_FN(CreateToolhelp32Snapshot).forwarded_safe()(TH32CS_SNAPPROCESS, 0);
        HANDLE hProcess = nullptr;
        uintptr_t resultAddress = 0;

        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);

            if (LI_FN(Process32First).forwarded_safe()(hSnapshot, &pe32)) {
                do {
                    if (std::string(pe32.szExeFile) == processName) {
                        hProcess = LI_FN(OpenProcess).forwarded_safe()(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
                        break;
                    }
                } while (LI_FN(Process32Next).forwarded_safe()(hSnapshot, &pe32));
            }

            LI_FN(CloseHandle).forwarded_safe()(hSnapshot);
        }

        if (hProcess != nullptr) {
            MODULEINFO moduleInfo;
            if (moduleName != nullptr) {
                HMODULE hModule = LI_FN(GetModuleHandleA).forwarded_safe()(moduleName);
                LI_FN(GetModuleInformation).forwarded_safe()(hProcess, hModule, &moduleInfo, sizeof(moduleInfo));
            } else {
                HMODULE hModule = LI_FN(GetModuleHandleA).forwarded_safe()(nullptr);
                LI_FN(GetModuleInformation).forwarded_safe()(hProcess, hModule, &moduleInfo, sizeof(moduleInfo));
            }

            auto startAddress = reinterpret_cast<uintptr_t>(moduleInfo.lpBaseOfDll);
            uintptr_t endAddress = startAddress + moduleInfo.SizeOfImage;

            int skipsUsed = skips;
            std::istringstream split(pattern);
            std::vector<int> signature = {};

            for (std::string each; std::getline(split, each, ' ');) {
                if (each == std::string(AY_OBFUSCATE("??")) || each == std::string(AY_OBFUSCATE("?"))) {
                    signature.push_back(-1);
                } else {
                    signature.push_back((int)(std::stoul(each, nullptr, 16)));
                }
            }

            uintptr_t searchEnd = endAddress - signature.size();

            for (auto i = startAddress; i < searchEnd; i++) {
                size_t j = 0;

                for (; j < signature.size(); j++) {
                    if (i + j >= searchEnd)
                        break;

                    if (signature[j] != -1 && (int)(*reinterpret_cast<std::byte*>(i + j)) != signature[j])
                        break;
                }

                if (j >= signature.size()) {
                    if (skipsUsed == 0) {
                        resultAddress = i;
                        break;
                    }

                    skipsUsed--;
                }
            }

            LI_FN(CloseHandle).forwarded_safe()(hProcess);
        }

        return resultAddress;
    }
};
