#include <Windows.h>
#include <Psapi.h>
#include <cstring>

MODULEINFO GetModuleInfo(const char* szModule)
{
        MODULEINFO modinfo = { 0 };
        HMODULE hModule = GetModuleHandleA(szModule);
        if (!hModule)
                return modinfo;
        GetModuleInformation(GetCurrentProcess(), hModule, &modinfo, sizeof(MODULEINFO));
        return modinfo;
}

DWORD64 FindPattern(const char* module, const char* pattern, const char* mask)
{
        MODULEINFO mInfo = GetModuleInfo(module);
        DWORD64 base = (DWORD64)mInfo.lpBaseOfDll;
        DWORD64 size = (DWORD64)mInfo.SizeOfImage;
        DWORD patternLength = (DWORD)strlen(mask);

        for (DWORD i = 0; i < size - patternLength; i++)
        {
                bool found = true;
                for (DWORD j = 0; j < patternLength; j++)
                {
                        found &= mask[j] == '?' || pattern[j] == *(char*)(base + i + j);
                }
                if (found)
                {
                        return base + i;
                }
        }

        return 0;
}
