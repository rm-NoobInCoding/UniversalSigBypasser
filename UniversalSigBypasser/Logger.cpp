#include "Logger.h"


const char* LogLevelToString(LogLevel level) {
    switch (level) {
    case LogLevel::INFO: return "INFO";
    case LogLevel::WARN: return "WARN";
    case LogLevel::E_ERROR: return "ERROR";
    default: return "UNKNOWN";
    }
}

void LogMessage(LogLevel level, const char* tag, int line, const std::string& message) {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()) % 1'000'000'000;

    struct tm timeinfo;
    localtime_s(&timeinfo, &time);

    std::ostringstream oss;
    oss << std::put_time(&timeinfo, "%Y-%m-%d %H:%M:%S") << "."
        << std::setfill('0') << std::setw(9) << ns.count()
        << " [" << LogLevelToString(level) << "] <" << tag << ":" << line << ">: " << message << "\n";

    std::ofstream log("SigBypasser.log", std::ios::app);
    log << oss.str();
}
