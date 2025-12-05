#include <Windows.h>
#include <iostream>
#include <cstdint>
#include <cstring>
#include "SignalScanner.h"
#include "Logger.h"

bool Patch(BYTE* address) {
    // Patch the target function to always return true.
    // mov al, 1; ret
    const BYTE patchBytes[] = { 0xB0, 0x01, 0xC3 };
    DWORD oldProtect;
    if (!VirtualProtect(address, sizeof(patchBytes), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        LogMessage(LogLevel::INFO, "UniversalPatch", __LINE__, (std::ostringstream() << "Failed to change protection at " << std::hex << address).str());
        return false;
    }

    std::memcpy(address, patchBytes, sizeof(patchBytes));
    FlushInstructionCache(GetCurrentProcess(), address, sizeof(patchBytes));
    VirtualProtect(address, sizeof(patchBytes), oldProtect, &oldProtect);
    return true;
}

int32_t ReadInt(const BYTE* ptr) {
    return *reinterpret_cast<const int32_t*>(ptr);
}

BYTE* FollowJump(BYTE* address) {
    if (*address == 0xE9 || *address == 0xE8) {
        int32_t offset = ReadInt(address + 1);
        return address + offset + 5;
    }
    else {
        LogMessage(LogLevel::INFO, "UniversalPatch", __LINE__,
            (std::ostringstream() << "Wrong jump instruction offset at: 0x"
                << std::hex << reinterpret_cast<uintptr_t>(address))
            .str());
        return nullptr;
    }
}

void UniversalPatch() {
    LogMessage(LogLevel::INFO, "UniversalPatch", __LINE__, "UniversalSigBypasser Loaded.");

    const char* patterns[] = {
        "48 8D 0D ?? ?? ?? ?? E9 ?? ?? ?? ?? CC CC CC CC 48 83 EC 28 E8 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 83 C4 28 C3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? E9 ?? ?? ?? ?? CC CC CC CC 48 8D 0D ?? ?? ?? ?? E9 ?? ?? ?? ?? CC CC CC CC",
        "48 8D ?? ?? ?? ?? ?? E9 ?? ?? ?? ?? CC CC CC CC 48 83 EC 28 33 D2 48 8D 4C 24 30 E8 ?? ?? ?? ?? 48 8B C8 E8 ?? ?? ?? ?? 48 89 ?? ?? ?? ?? ?? 48 83 C4 28 C3 CC CC CC CC CC CC CC CC CC CC CC CC 48 8D ?? ?? ?? ?? ?? E9",
        "48 83 EC 28 48 8D ?? ?? ?? ?? ?? 48 89 44 24 30 E8 ?? ?? ?? ?? 48 8B C8 48 8D 54 24 30 E8 ?? ?? ?? ?? 48 83 C4 28 C3 CC CC CC CC CC CC CC CC CC 48 83 EC 28 48 8D ?? ?? ?? ?? ?? 48 89 44 24 30 E8 ?? ?? ?? ?? 48 8B C8 48 8D 54 24 30 E8 ?? ?? ?? ?? 48 83 C4 28 C3", //Lost Soul Aside
        "40 53 48 83 EC 20 48 8B D9 FF 15 ?? ?? ?? ?? 48 8B C8 48 83 C4 20 5B C3 41 8B D8",
        "41 56 41 57 48 83 EC 50 4C 8B F1 41 8B D8",
        "48 8B C4 48 89 58 08 48 89 70 10 48 89 78 18 41 56 48 81 ?? ?? ?? ?? 00 45 8B F1"
    };

    DWORD64 addr64 = 0;
    int offset = 0;

    for (int i = 0; i < sizeof(patterns) / sizeof(patterns[0]); ++i) {
        addr64 = FindPatternIDA(NULL, patterns[i]);
        if (addr64) {
            if (i == 0) offset = 0x37;
            else if (i == 1) offset = 0x47;
			else if (i == 2) offset = 0x1D; //Lost Soul Aside
            else if (i == 3) offset = 0x2A;
            else if (i == 4) offset = 0x1B;
            else if (i == 5) offset = 0x26;
            LogMessage(LogLevel::INFO, "UniversalPatch", __LINE__, (std::ostringstream() << "Pattern " << i + 1 << " found at 0x" << std::hex << addr64).str());
            break;
        }
    }

    if (!addr64) {
        LogMessage(LogLevel::E_ERROR, "UniversalPatch", __LINE__, "Pattern not found!");
        return;
    }

    BYTE* baseAddress = reinterpret_cast<BYTE*>(addr64);

    BYTE* firstJump = FollowJump(baseAddress + offset);
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
