#include <windows.h>
#include <cstddef>

#include <obfuscate.hpp>
#include <lazy_importer.hpp>
#include <SigScanner.hpp>

auto inject(HMODULE hModule) -> void {
    LI_FN(OutputDebugStringA).forwarded_safe()(AY_OBFUSCATE("Searching for offset..."));

    auto offset = SigScanner::scanMemoryPattern(AY_OBFUSCATE("Minecraft.Windows.exe"), AY_OBFUSCATE("B0 01 48 8B 4C 24 40 48 33 CC E8 ? ? ? ? 48 8B 5C 24 68 48 8B 74 24 70 48 83 C4 50 5F C3 48 8B 83 60 01 00 00"));

    if (!offset) {
        LI_FN(OutputDebugStringA).forwarded_safe()(AY_OBFUSCATE("Unable to find offset!"));
        goto end;
    }

    LI_FN(OutputDebugStringA).forwarded_safe()(AY_OBFUSCATE("Found offset!"));

    DWORD oldProtect;
    LI_FN(VirtualProtect).forwarded_safe()(reinterpret_cast<void*>(offset), 0x2, PAGE_EXECUTE_READWRITE, &oldProtect);

    *reinterpret_cast<std::byte*>(offset + 0x1) = static_cast<std::byte>(0x0);

    LI_FN(VirtualProtect).forwarded_safe()(reinterpret_cast<void*>(offset), 0x2, oldProtect, &oldProtect);

   LI_FN(OutputDebugStringA).forwarded_safe()(AY_OBFUSCATE("Successfully patched offset!"));

    end:
    LI_FN(FreeLibraryAndExitThread).forwarded_safe()(hModule, 0);
}

auto APIENTRY DllMain(HMODULE hModule, const DWORD ul_reason_for_call, LPVOID lpReserved) -> BOOL {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
        LI_FN(CreateThread).forwarded_safe()(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(inject), hModule, 0, nullptr);

    return TRUE;
}