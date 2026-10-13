#include "core/diagnostics_internal.hpp"
#include "core/diagnostic_archive.hpp"
#include "core/handle.hpp"
#include <bcrypt.h>
#include <shellapi.h>
#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <set>
#include <system_error>
#include <thread>
#include <type_traits>
#include <vector>

namespace base::diagnostics {
namespace {
using Clock = std::chrono::steady_clock;
constexpr std::uint64_t file_limit = 8 * 1024 * 1024;
constexpr std::uint64_t evidence_limit = 1024ull * 1024 * 1024;

std::string Quote(std::string_view value) {
    std::string out = "\"";
    auto length = std::min<std::size_t>(value.size(), 16384);
    if (length < value.size())
        while (length && (static_cast<unsigned char>(value[length]) & 0xc0) == 0x80)
            --length;
    const auto bounded = value.substr(0, length);
    const bool utf8 = bounded.empty() ||
        MultiByteToWideChar(
            CP_UTF8, MB_ERR_INVALID_CHARS, bounded.data(), static_cast<int>(bounded.size()), nullptr, 0) != 0;
    for (const auto c : bounded) {
        const auto byte = static_cast<unsigned char>(c);
        if (c == '\\' || c == '"') {
            out += '\\';
            out += c;
        } else if (byte < 32 || (!utf8 && byte >= 128)) {
            constexpr char digits[] = "0123456789abcdef";
            out += "\\u00";
            out += digits[byte >> 4];
            out += digits[byte & 15];
        } else
            out += c;
    }
    if (value.size() > length)
        out += "[truncated]";
    return out + '"';
}

std::string Utc() {
    SYSTEMTIME time{};
    GetSystemTime(&time);
    char text[40]{};
    snprintf(text, sizeof(text), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", time.wYear, time.wMonth, time.wDay,
        time.wHour, time.wMinute, time.wSecond, time.wMilliseconds);
    return text;
}

struct Recorder {
    std::mutex lifecycle;
    std::mutex mutex;
    std::condition_variable_any wake;
    Archive archive;
    std::wstring path;
    std::string phase = "application startup";
    float progress{};
    DWORD error{};
    std::uint64_t bytes{}, sequence{}, records_bytes{}, evidence_bytes{};
    bool records_limited{}, evidence_limited{};
    std::set<std::string> artifacts;
    Limits limits;
    Clock::time_point started = Clock::now(), changed = started, updated = started;
    std::jthread monitor;

    ~Recorder() { Stop(); }

    void Stop() noexcept {
        const std::lock_guard lifecycle_lock(lifecycle);
        monitor.request_stop();
        wake.notify_all();
        if (monitor.joinable())
            monitor.join();
        const std::lock_guard lock(mutex);
        if (const auto failure = archive.Close())
            error = failure;
    }
};

Recorder& State() {
    static Recorder state;
    return state;
}

void Append(Recorder& state, std::string_view text) {
    if (const auto error = state.archive.Append(text)) {
        state.error = error;
        state.archive.Close();
        return;
    }
    state.bytes += text.size();
}

std::wstring TemporaryDirectory() {
    std::array<wchar_t, 32768> text{};
    const auto length = GetTempPathW(static_cast<DWORD>(text.size()), text.data());
    if (!length || length >= text.size())
        throw std::system_error(ERROR_PATH_NOT_FOUND, std::system_category());
    return (std::filesystem::path(std::wstring(text.data(), length)) / L"lifusbounce" / L"logs").wstring();
}

std::wstring Directory() {
    std::array<wchar_t, 32768> text{};
    const auto length =
        GetEnvironmentVariableW(L"LOCALAPPDATA", text.data(), static_cast<DWORD>(text.size()));
    return length && length < text.size()
        ? (std::filesystem::path(std::wstring(text.data(), length)) / L"lifusbounce" / L"logs").wstring()
        : TemporaryDirectory();
}

std::string ExecutableHash() {
    std::array<wchar_t, 32768> name{};
    const auto length = GetModuleFileNameW(nullptr, name.data(), static_cast<DWORD>(name.size()));
    if (!length || length >= name.size())
        return {};
    std::ifstream input(std::filesystem::path(std::wstring(name.data(), length)), std::ios::binary);
    if (!input)
        return {};
    const auto size = std::filesystem::file_size(std::wstring(name.data(), length));
    if (size > 64 * 1024 * 1024)
        return {};
    std::vector<std::byte> bytes(static_cast<std::size_t>(size));
    input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    return input ? Sha256(bytes) : std::string{};
}
}

bool Initialize(std::wstring_view directory, Limits limits) noexcept {
    try {
        auto& state = State();
        const std::lock_guard lifecycle_lock(state.lifecycle);
        Retention retention;
        {
            const std::lock_guard lock(state.mutex);
            if (state.archive)
                return true;
            if (state.monitor.joinable())
                return false;
            auto folder = directory.empty() ? Directory() : std::wstring(directory);
            try {
                std::filesystem::create_directories(folder);
            } catch (...) {
                if (!directory.empty())
                    throw;
                folder = TemporaryDirectory();
                std::filesystem::create_directories(folder);
            }
            state.path = (std::filesystem::path(folder) / L"lifus-diagnostic-latest.zip").wstring();
            state.error = state.archive.Open(state.path);
            if (state.error && directory.empty() && state.error != ERROR_SHARING_VIOLATION) {
                const auto fallback = TemporaryDirectory();
                std::filesystem::create_directories(fallback);
                folder = fallback;
                state.path = (std::filesystem::path(folder) / L"lifus-diagnostic-latest.zip").wstring();
                state.error = state.archive.Open(state.path);
            }
            if (state.error) {
                state.archive.Close();
                return false;
            }
            retention = Prune(folder);
            state.bytes = state.sequence = state.records_bytes = state.evidence_bytes = 0;
            state.records_limited = state.evidence_limited = false;
            state.artifacts.clear();
            state.limits.records = std::clamp(limits.records, 4096ull, file_limit);
            state.limits.evidence = std::clamp(limits.evidence, 4096ull, evidence_limit);
            state.phase = "application startup";
            state.progress = 0;
            state.error = ERROR_SUCCESS;
            state.started = state.changed = state.updated = Clock::now();
        }
        const auto hash = ExecutableHash();
        Write("run_started",
            {{"schema", 2u}, {"executable_sha256", hash}, {"compiled", __DATE__ " " __TIME__},
                {"log_limit_bytes", state.limits.records}, {"evidence_limit_bytes", state.limits.evidence},
                {"contains_native_code", true}, {"contains_runtime_pointer_values", true},
                {"contains_full_heap_dump", false}, {"contains_player_names", false},
                {"uploads_automatically", false}, {"container", "zip"}, {"retained_runs", 1u}});
        Write("diagnostic_retention", {{"removed", retention.removed}, {"win32", retention.error}});
        MemoryStatus("startup");
        state.monitor = std::jthread([&state](std::stop_token stop) {
            std::unique_lock lock(state.mutex);
            while (!stop.stop_requested()) {
                state.wake.wait_for(lock, stop, std::chrono::seconds(5), [] { return false; });
                if (stop.stop_requested())
                    break;
                const auto phase = state.phase;
                const auto progress = state.progress;
                const auto now = Clock::now();
                const auto phase_ms =
                    std::chrono::duration_cast<std::chrono::milliseconds>(now - state.changed).count();
                const auto update_ms =
                    std::chrono::duration_cast<std::chrono::milliseconds>(now - state.updated).count();
                lock.unlock();
                Write("heartbeat",
                    {{"phase", phase}, {"progress_percent", progress * 100.0f}, {"phase_ms", phase_ms},
                        {"since_update_ms", update_ms}});
                MemoryStatus("heartbeat");
                lock.lock();
                if (const auto error = state.archive.Flush())
                    state.error = error;
            }
        });
        return true;
    } catch (...) {
        try {
            const std::lock_guard lock(State().mutex);
            State().archive.Close();
            State().error = ERROR_WRITE_FAULT;
        } catch (...) {
        }
        return false;
    }
}

void Shutdown() noexcept {
    Write("run_stopped");
    State().Stop();
}

bool Enabled() noexcept {
    const std::lock_guard lock(State().mutex);
    return static_cast<bool>(State().archive);
}

DWORD Error() noexcept {
    const std::lock_guard lock(State().mutex);
    return State().error;
}

std::wstring Path() {
    const std::lock_guard lock(State().mutex);
    return State().path;
}

void OpenFolder() noexcept {
    try {
        const auto path = Path();
        if (Enabled() && !path.empty()) {
            const auto result = reinterpret_cast<INT_PTR>(ShellExecuteW(nullptr, L"open",
                std::filesystem::path(path).parent_path().c_str(), nullptr, nullptr, SW_SHOWNORMAL));
            if (result > 32)
                return;
        }
        wchar_t message[160]{};
        swprintf_s(message, L"could not open diagnostic logs (win32 %lu)", Error());
        MessageBoxW(nullptr, message, L"lifusbounce", MB_OK | MB_ICONWARNING);
    } catch (...) {
    }
}

namespace {
bool Record(std::string_view event, std::initializer_list<Field> fields, std::string_view payload,
    bool evidence) noexcept {
    try {
        auto& state = State();
        const std::lock_guard lock(state.mutex);
        if (!state.archive || (evidence ? state.evidence_limited : state.records_limited))
            return false;
        const auto elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - state.started).count();
        std::string line = "{\"utc\":" + Quote(Utc()) + ",\"elapsed_ms\":" + std::to_string(elapsed) +
            ",\"sequence\":" + std::to_string(state.sequence + 1) + ",\"event\":" + Quote(event);
        for (const auto& field : fields) {
            line += ',' + Quote(field.name) + ':';
            std::visit(
                [&](const auto& value) {
                    using Value = std::decay_t<decltype(value)>;
                    if constexpr (std::is_same_v<Value, std::string_view>)
                        line += Quote(value);
                    else if constexpr (std::is_same_v<Value, bool>)
                        line += value ? "true" : "false";
                    else if constexpr (std::is_same_v<Value, double>)
                        line += std::isfinite(value) ? std::to_string(value) : "null";
                    else
                        line += std::to_string(value);
                },
                field.value);
        }
        if (!payload.empty())
            line += ",\"payload\":\"" + std::string(payload) + '"';
        line += "}\n";
        auto& size = evidence ? state.evidence_bytes : state.records_bytes;
        const auto limit = evidence ? state.limits.evidence : state.limits.records;
        if (size + line.size() + 1024 > limit) {
            const auto marker =
                "{\"event\":" + Quote(evidence ? "evidence_limit_reached" : "log_limit_reached") +
                ",\"sequence\":" + std::to_string(++state.sequence) +
                ",\"limit_bytes\":" + std::to_string(limit) +
                ",\"message\":\"restart to create a fresh diagnostic log\"}\n";
            Append(state, marker);
            size += marker.size();
            (evidence ? state.evidence_limited : state.records_limited) = true;
            state.archive.Flush();
            return false;
        }
        ++state.sequence;
        Append(state, line);
        size += line.size();
        return static_cast<bool>(state.archive);
    } catch (...) {
    }
    return false;
}
}

void Write(std::string_view event, std::initializer_list<Field> fields) noexcept {
    Record(event, fields, {}, false);
}

bool EvidenceRecord(
    std::string_view event, std::initializer_list<Field> fields, std::string_view payload) noexcept {
    return Record(event, fields, payload, true);
}

bool KnownArtifact(std::string_view key) {
    const std::lock_guard lock(State().mutex);
    return State().artifacts.contains(std::string(key));
}

void RememberArtifact(std::string_view key) {
    const std::lock_guard lock(State().mutex);
    State().artifacts.emplace(key);
}

void Phase(std::string_view name, float progress) noexcept {
    try {
        auto& state = State();
        const std::lock_guard lock(state.mutex);
        if (state.phase != name) {
            state.phase = name;
            state.changed = Clock::now();
        }
        state.progress = std::isfinite(progress) ? std::clamp(progress, 0.0f, 1.0f) : 0.0f;
        state.updated = Clock::now();
    } catch (...) {
    }
}

std::string Hex(std::uint64_t value) {
    std::array<char, 18> text{};
    text[0] = '0';
    text[1] = 'x';
    const auto end = std::to_chars(text.data() + 2, text.data() + text.size(), value, 16);
    return {text.data(), end.ptr};
}

std::string Sha256(std::span<const std::byte> bytes) noexcept {
    BCRYPT_ALG_HANDLE algorithm{};
    BCRYPT_HASH_HANDLE hash{};
    try {
        if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
            return {};
        const auto created = BCryptCreateHash(algorithm, &hash, nullptr, 0, nullptr, 0, 0);
        if (created < 0) {
            BCryptCloseAlgorithmProvider(algorithm, 0);
            return {};
        }
        bool valid = true;
        for (std::size_t offset = 0; offset < bytes.size() && valid;) {
            const auto count = static_cast<ULONG>(std::min<std::size_t>(bytes.size() - offset, 1024 * 1024));
            valid =
                BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<std::byte*>(bytes.data() + offset)),
                    count, 0) >= 0;
            offset += count;
        }
        std::array<UCHAR, 32> digest{};
        valid = valid && BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) >= 0;
        BCryptDestroyHash(hash);
        hash = nullptr;
        BCryptCloseAlgorithmProvider(algorithm, 0);
        algorithm = nullptr;
        if (!valid)
            return {};
        constexpr char digits[] = "0123456789abcdef";
        std::string out;
        for (const auto byte : digest) {
            out += digits[byte >> 4];
            out += digits[byte & 15];
        }
        return out;
    } catch (...) {
        if (hash)
            BCryptDestroyHash(hash);
        if (algorithm)
            BCryptCloseAlgorithmProvider(algorithm, 0);
        return {};
    }
}
}
