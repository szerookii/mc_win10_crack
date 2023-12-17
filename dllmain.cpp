#include <windows.h>
#include <Psapi.h>
#include <cstddef>

#include <xorstr.hpp>
#include <lazy_importer.hpp>
#include <CallStack_Spoofer.h>

#define WINVER 0x0A00
#define _WIN32_WINNT 0x0A00

#define INRANGE(x, a, b) (x >= a && x <= b)
#define GET_BYTE(x) (GET_BITS(x[0]) << 4 | GET_BITS(x[1]))
#define GET_BITS(x)                                                            \
  (INRANGE((x & (~0x20)), 'A', 'F') ? ((x & (~0x20)) - 'A' + 0xa)              \
                                    : (INRANGE(x, '0', '9') ? x - '0' : 0))

auto findSig(const char* szSignature) -> uintptr_t {
    SPOOF_FUNC;

    const char* pattern = szSignature;
    uintptr_t firstMatch = 0;

    static const auto rangeStart = (uintptr_t) LI_FN(GetModuleHandleA).forwarded_safe_cached()("Minecraft.Windows.exe");
    static MODULEINFO miModInfo;
    static bool init = false;

    if (!init) {
        init = true;
        LI_FN(GetModuleInformation).forwarded_safe_cached()(LI_FN(GetCurrentProcess).forwarded_safe_cached()(), (HMODULE) rangeStart, &miModInfo, sizeof(MODULEINFO));
    }

    static const uintptr_t rangeEnd = rangeStart + miModInfo.SizeOfImage;

    BYTE patByte = GET_BYTE(pattern);
    const char* oldPat = pattern;

    for (uintptr_t pCur = rangeStart; pCur < rangeEnd; pCur++) {
        if (!*pattern)
            return firstMatch;

        while (*(PBYTE) pattern == ' ')
            pattern++;

        if (!*pattern)
            return firstMatch;

        if (oldPat != pattern) {
            oldPat = pattern;
            if (*(PBYTE) pattern != '\?')
                patByte = GET_BYTE(pattern);
        }

        if (*(PBYTE) pattern == '\?' || *(BYTE *) pCur == patByte) {
            if (!firstMatch)
                firstMatch = pCur;

            if (!pattern[2] || !pattern[1])
                return firstMatch;

            pattern += 2;
        } else {
            pattern = szSignature;
            firstMatch = 0;
        }
    }

    return 0;
}


auto inject(HMODULE hModule) -> void {
    SPOOF_FUNC;

    LI_FN(OutputDebugStringA).forwarded_safe_cached()(xorstr_("Searching for offsets..."));

    auto offset = findSig(xorstr_("B0 01 48 8B 4C 24 40 48 33 CC E8 ? ? ? ? 48 8B 5C 24 68 48 8B 74 24 70 48 83 C4 50 5F C3 48 8B 83 60 01 00 00"));

    if(!offset) {
        LI_FN(OutputDebugStringA).forwarded_safe_cached()(xorstr_("Unable to find offset!"));
        return;
    }

    LI_FN(OutputDebugStringA).forwarded_safe_cached()(xorstr_("Found offset!"));

    DWORD oldProtect;
    LI_FN(VirtualProtect).forwarded_safe_cached()(reinterpret_cast<void*>(offset), 0x2, PAGE_EXECUTE_READWRITE, &oldProtect);

    *reinterpret_cast<std::byte*>(offset + 0x1) = static_cast<std::byte>(0x0);

    LI_FN(VirtualProtect).forwarded_safe_cached()(reinterpret_cast<void*>(offset), 0x2, oldProtect, &oldProtect);

    LI_FN(OutputDebugStringA).forwarded_safe_cached()(xorstr_("Successfully patched offset!"));

    LI_FN(FreeLibraryAndExitThread).forwarded_safe_cached()(hModule, NULL);
}

auto APIENTRY DllMain(HMODULE hModule, const DWORD ul_reason_for_call, LPVOID lpReserved) -> BOOL {
    SPOOF_FUNC;

    if(ul_reason_for_call == DLL_PROCESS_ATTACH) {
        LI_FN(CreateThread).forwarded_safe_cached()(nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(inject), hModule, NULL, nullptr);
    }

    return TRUE;
}