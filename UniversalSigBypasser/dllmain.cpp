#include <Windows.h>
#include <iostream>
#include <cstdint>
#include "SignalScanner.h"
#include "logger.h"

bool Patch(BYTE* address) {
    DWORD oldProtect;
    if (!VirtualProtect(address, 1, PAGE_EXECUTE_READWRITE, &oldProtect )) {
        LogMessage(LogLevel::INFO, "UniversalPatch", __LINE__, (std::ostringstream() << "Failed to change protection at " << std::hex << address).str());

        return false;
    }
    memset(address, 0xC3, 1);
    VirtualProtect(address, 1, oldProtect, &oldProtect);
    return true;
}

int32_t ReadInt(const BYTE* ptr) {
    return *reinterpret_cast<const int32_t*>(ptr);
}

BYTE* FollowJump(BYTE* address) {
    if (*address == 0xE9) {
        int32_t offset = ReadInt(address + 1);
        return address + offset + 5;
    }
    else {
        std::cout << "Wrong jump instruction offset at: 0x" << std::hex << reinterpret_cast<uintptr_t>(address) << "\n";
        return nullptr;
    }
}

void UniversalPatch() {
	LogMessage(LogLevel::INFO, "UniversalPatch", __LINE__, "UniversalSigBypasser Loaded.");
    const char* pattern = "\x48\x8D\x0D\x00\x00\x00\x00\xE9\x00\x00\x00\x00\xCC\xCC\xCC\xCC\x48\x83\xEC\x28\xE8\x00\x00\x00\x00\x48\x89\x05\x00\x00\x00\x00\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x8D\x0D\x00\x00\x00\x00\xE9\x00\x00\x00\x00\xCC\xCC\xCC\xCC\x48\x8D\x0D\x00\x00\x00\x00\xE9\x00\x00\x00\x00\xCC\xCC\xCC\xCC";
    const char* mask = "xxx????x????xxxxxxxxx????xxx????xxxxx???????????xxx????x????xxxxxxx????x????xxxx";
    DWORD64 addr64 = FindPattern(NULL, (char*)pattern, (char*)mask);

    if (!addr64) {
        LogMessage(LogLevel::E_ERROR, "UniversalPatch", __LINE__, "Pattern not found!");
        return;
    }
    LogMessage(LogLevel::INFO, "UniversalPatch", __LINE__, (std::ostringstream() << "Pattern found at 0x" << std::hex << addr64).str());

    BYTE* baseAddress = reinterpret_cast<BYTE*>(addr64);


    BYTE* firstJump = FollowJump(baseAddress + 0x37);
    if (firstJump) {
        if (Patch(firstJump))
            LogMessage(LogLevel::INFO, "UniversalPatch", __LINE__, (std::ostringstream() << "Patch applied at 0x" << std::hex << reinterpret_cast<uintptr_t>(firstJump)).str());
        else
            LogMessage(LogLevel::E_ERROR, "UniversalPatch", __LINE__, "Failed to patch.");
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        UniversalPatch();
        LogMessage(LogLevel::INFO, "UniversalPatch", __LINE__, "Bypass process ended.");
    }
    return TRUE;
}
