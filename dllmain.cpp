#include <windows.h>
#include <cstddef>

#include <xorstr.hpp>
#include <lazy_importer.hpp>
#include <CallStack_Spoofer.h>
#include <SigScanner.hpp>

#define WINVER 0x0A00
#define _WIN32_WINNT 0x0A00

auto inject(HMODULE hModule) -> void {
    SPOOF_FUNC;

    SPOOF_CALL(LI_FN(OutputDebugStringA).forwarded_safe())(xorstr_("Searching for offset..."));

    auto offset = SigScanner::scanMemoryPattern(xorstr_("Minecraft.Windows.exe"), xorstr_("B0 01 48 8B 4C 24 40 48 33 CC E8 ? ? ? ? 48 8B 5C 24 68 48 8B 74 24 70 48 83 C4 50 5F C3 48 8B 83 60 01 00 00"));

    if (!offset) {
        SPOOF_CALL(LI_FN(OutputDebugStringA).forwarded_safe())(xorstr_("Unable to find offset!"));
        goto end;
    }

    SPOOF_CALL(LI_FN(OutputDebugStringA).forwarded_safe())(xorstr_("Found offset!"));

    DWORD oldProtect;
    SPOOF_CALL(LI_FN(VirtualProtect).forwarded_safe())(reinterpret_cast<void *>(offset), 0x2, PAGE_EXECUTE_READWRITE, &oldProtect);

    *reinterpret_cast<std::byte *>(offset + 0x1) = static_cast<std::byte>(0x0);

    SPOOF_CALL(LI_FN(VirtualProtect).forwarded_safe())(reinterpret_cast<void *>(offset), 0x2, oldProtect, &oldProtect);

    SPOOF_CALL(LI_FN(OutputDebugStringA).forwarded_safe())(xorstr_("Successfully patched offset!"));

    end:
    SPOOF_CALL(LI_FN(FreeLibraryAndExitThread).forwarded_safe())(hModule, NULL);
}

auto APIENTRY DllMain(HMODULE hModule, const DWORD ul_reason_for_call, LPVOID lpReserved) -> BOOL {
    SPOOF_FUNC;

    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        SPOOF_CALL(LI_FN(CreateThread).forwarded_safe())(nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(inject), hModule,NULL, nullptr);
    }

    return TRUE;
}