#include <Windows.h>
#include <Psapi.h>
#include <string.h>
#include <sstream>

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

DWORD64 FindPatternIDA(const char* module, const char* patternIDA)
{
    std::string patternBytes;
    std::string patternMask;
    std::stringstream ss(patternIDA);
    std::string word;

    while (ss >> word)
    {
        if (word == "??") {
            patternBytes.push_back('\x00');
            patternMask.push_back('?');
        }
        else {
            patternBytes.push_back((char)strtoul(word.c_str(), nullptr, 16));
            patternMask.push_back('x');
        }
    }

    return FindPattern(module, patternBytes.c_str(), patternMask.c_str());
}