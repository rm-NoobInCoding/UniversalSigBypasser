#pragma once
#include <Windows.h>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>

enum class LogLevel {
    INFO,
    WARN,
    E_ERROR
};

const char* LogLevelToString(LogLevel level);

void LogMessage(LogLevel level, const char* tag, int line, const std::string& message);
