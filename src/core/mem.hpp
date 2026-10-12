#pragma once
#include "core/handle.hpp"
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

namespace base {
struct ProcessInfo {
    DWORD pid;
    std::wstring name;
};

struct ModuleInfo {
    std::wstring name;
    std::uintptr_t address;
    std::size_t size;
};

struct ThreadEntry {
    DWORD tid;
    std::uintptr_t teb;
};

struct ReadResult {
    std::size_t transferred = 0;
    DWORD error = ERROR_SUCCESS;

    [[nodiscard]] bool Complete() const noexcept { return error == ERROR_SUCCESS; }
};

[[nodiscard]] std::wstring ErrorText(DWORD error);
[[nodiscard]] std::vector<ProcessInfo> Processes(DWORD& error);

class Memory {
  public:
    [[nodiscard]] DWORD Attach(DWORD pid) noexcept;

    void Detach() noexcept {
        driver_.Reset();
        pid_ = 0;
    }

    [[nodiscard]] DWORD Pid() const noexcept { return pid_; }

    [[nodiscard]] bool Attached() const noexcept { return static_cast<bool>(driver_); }

    [[nodiscard]] ReadResult ReadBytes(std::uintptr_t address, std::span<std::byte> output) const noexcept;

    template <class T>
        requires std::is_trivially_copyable_v<T>
    [[nodiscard]] std::optional<T> Read(std::uintptr_t address, DWORD* error = nullptr) const noexcept {
        T value{};
        const auto result = ReadBytes(address, std::as_writable_bytes(std::span<T>(&value, 1)));
        if (error)
            *error = result.error;
        if (!result.Complete())
            return std::nullopt;
        return value;
    }

    [[nodiscard]] std::vector<ModuleInfo> Modules(DWORD& error) const;
    [[nodiscard]] std::optional<bool> Is64Bit(DWORD& error) const noexcept;
    [[nodiscard]] std::vector<ThreadEntry> Threads(DWORD& error) const;

  private:
    UniqueHandle driver_;
    DWORD pid_ = 0;
};
}
