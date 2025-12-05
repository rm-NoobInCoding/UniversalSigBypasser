#include <Windows.h>
#include <Psapi.h>

MODULEINFO GetModuleInfo(const char* szModule)
{
    MODULEINFO modinfo = { 0 };
    HMODULE hModule = GetModuleHandleA(szModule);
    if (!hModule) return modinfo;
    GetModuleInformation(GetCurrentProcess(), hModule, &modinfo, sizeof(MODULEINFO));
    return modinfo;
}

DWORD64 FindPattern(const char* module, const char* pattern, const char* mask)
{
    MODULEINFO mInfo = GetModuleInfo(module);

    unsigned char* base = (unsigned char*)mInfo.lpBaseOfDll;
    size_t size = (size_t)mInfo.SizeOfImage;
    size_t patternLength = (size_t)strlen(mask);

    if (size == 0 || patternLength == 0) return 0;

    for (size_t i = 0; i < size - patternLength; i++)
    {
        bool found = true;
        for (size_t j = 0; j < patternLength; j++)
        {
            if (mask[j] != '?' && pattern[j] != (char)base[i + j])
            {
                found = false;
                break;
            }
        }

        if (found)
        {
            return (DWORD64)base + i;
        }
    }

    return 0;
}