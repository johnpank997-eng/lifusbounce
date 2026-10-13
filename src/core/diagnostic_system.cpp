#include "core/diagnostics.hpp"
#include <psapi.h>
#include <new>
#include <stdexcept>
#include <system_error>
#include <typeinfo>

namespace base::diagnostics {
void MemoryStatus(std::string_view reason) noexcept {
    MEMORYSTATUSEX memory{sizeof(memory)};
    PERFORMANCE_INFORMATION performance{sizeof(performance)};
    PROCESS_MEMORY_COUNTERS_EX process{};
    process.cb = sizeof(process);
    const auto physical_ok = GlobalMemoryStatusEx(&memory) != 0;
    const auto commit_ok = GetPerformanceInfo(&performance, sizeof(performance)) != 0;
    const auto process_ok = GetProcessMemoryInfo(GetCurrentProcess(),
                                reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&process), sizeof(process)) != 0;
    Write("memory_status",
        {{"reason", reason}, {"physical_available", physical_ok ? memory.ullAvailPhys : 0},
            {"physical_total", physical_ok ? memory.ullTotalPhys : 0},
            {"commit_bytes", commit_ok ? performance.CommitTotal * performance.PageSize : 0},
            {"commit_limit", commit_ok ? performance.CommitLimit * performance.PageSize : 0},
            {"process_private_bytes", process_ok ? process.PrivateUsage : 0},
            {"process_working_set", process_ok ? process.WorkingSetSize : 0},
            {"physical_available_known", physical_ok}, {"commit_known", commit_ok},
            {"process_known", process_ok}});
}

void Exception(std::string_view stage, const std::exception& error) noexcept {
    const char* category = dynamic_cast<const std::bad_alloc*>(&error) ? "allocation failure"
        : dynamic_cast<const std::length_error*>(&error)               ? "container length error"
        : dynamic_cast<const std::out_of_range*>(&error)               ? "out of range"
        : dynamic_cast<const std::invalid_argument*>(&error)           ? "invalid argument"
        : dynamic_cast<const std::system_error*>(&error)               ? "system error"
                                                                       : "standard exception";
    Write("exception",
        {{"stage", stage}, {"category", category}, {"type", typeid(error).name()},
            {"message", error.what()}});
    MemoryStatus("exception");
}
}
