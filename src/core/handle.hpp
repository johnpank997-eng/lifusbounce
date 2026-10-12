#pragma once
#include <windows.h>
#include <utility>

namespace base {
class UniqueHandle {
  public:
    UniqueHandle() = default;

    explicit UniqueHandle(HANDLE value) noexcept : value_(value) {}

    ~UniqueHandle() { Reset(); }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept : value_(other.Release()) {}

    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other)
            Reset(other.Release());
        return *this;
    }

    [[nodiscard]] HANDLE Get() const noexcept { return value_; }

    [[nodiscard]] explicit operator bool() const noexcept { return value_ && value_ != INVALID_HANDLE_VALUE; }

    HANDLE Release() noexcept { return std::exchange(value_, nullptr); }

    void Reset(HANDLE value = nullptr) noexcept {
        if (*this)
            CloseHandle(value_);
        value_ = value;
    }

  private:
    HANDLE value_ = nullptr;
};
}
