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
        LogMessage(LogLevel::INFO, "UniversalPatch", __LINE__,
                   (std::ostringstream() << "Failed to change protection at "
                                         << std::hex << address)
                       .str());
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
    if (*address == 0xE9) {
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
        "\x48\x8D\x0D\x00\x00\x00\x00\xE9\x00\x00\x00\x00\xCC\xCC\xCC\xCC\x48\x83\xEC\x28\xE8\x00\x00\x00\x00\x48\x89\x05\x00\x00\x00\x00\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x8D\x0D\x00\x00\x00\x00\xE9\x00\x00\x00\x00\xCC\xCC\xCC\xCC\x48\x8D\x0D\x00\x00\x00\x00\xE9\x00\x00\x00\x00\xCC\xCC\xCC\xCC",
        "\x40\x53\x48\x83\xEC\x20\x48\x8B\xD9\xFF\x15\x00\x00\x00\x00\x48\x8B\xC8\x48\x83\xC4\x20\x5B\xC3\x41\x8B\xD8",
        "\x41\x56\x41\x57\x48\x83\xEC\x50\x4C\x8B\xF1\x41\x8B\xD8",
        "\x48\x8B\xC4\x48\x89\x58\x08\x48\x89\x70\x10\x48\x89\x78\x18\x41\x56\x48\x81\xEC\x00\x00\x00\x00\x45\x8B\xF1"
    };

    const char* masks[] = {
        "xxx????x????xxxxxxxxx????xxx????xxxxx???????????xxx????x????xxxxxxx????x????xxxx",
        "xxxxxxxxxxx????xxxxxxxxx",
        "xxxxxxxxxxxxxx",
        "xxxxxxxxxxxxxxxxxxx????xx"
    };

    DWORD64 addr64 = 0;
    int offset = 0;

    for (int i = 0; i < sizeof(patterns) / sizeof(patterns[0]); ++i) {
        addr64 = FindPattern(NULL, patterns[i], masks[i]);
        if (addr64) {
            if (i == 0) offset = 0x37;
            else if (i == 1) offset = 0x2A;
            else if (i == 2) offset = 0x1B;
            else if (i == 3) offset = 0x26;
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
