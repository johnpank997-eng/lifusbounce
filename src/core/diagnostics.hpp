#pragma once
#include <windows.h>
#include <concepts>
#include <cstdint>
#include <exception>
#include <initializer_list>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <variant>

namespace base::diagnostics {
struct Field {
    std::string_view name;
    std::variant<std::string_view, std::uint64_t, std::int64_t, double, bool> value;

    Field(std::string_view key, std::string_view text) : name(key), value(text) {}

    Field(std::string_view key, const std::string& text) : Field(key, std::string_view(text)) {}

    Field(std::string_view key, const char* text) : Field(key, std::string_view(text ? text : "")) {}

    Field(std::string_view key, bool flag) : name(key), value(flag) {}

    template <std::unsigned_integral T>
    Field(std::string_view key, T number) : name(key), value(static_cast<std::uint64_t>(number)) {}

    template <std::signed_integral T>
    Field(std::string_view key, T number) : name(key), value(static_cast<std::int64_t>(number)) {}

    template <std::floating_point T>
    Field(std::string_view key, T number) : name(key), value(static_cast<double>(number)) {}
};

struct Limits {
    std::uint64_t records = 8 * 1024 * 1024;
    std::uint64_t evidence = 1024ull * 1024 * 1024;
};

bool Initialize(std::wstring_view directory = {}, Limits limits = {}) noexcept;
void Shutdown() noexcept;
bool Enabled() noexcept;
DWORD Error() noexcept;
std::wstring Path();
void OpenFolder() noexcept;
void Write(std::string_view event, std::initializer_list<Field> fields = {}) noexcept;
void Phase(std::string_view name, float progress = 0.0f) noexcept;
std::string Hex(std::uint64_t value);
std::string Sha256(std::span<const std::byte> bytes) noexcept;
bool Artifact(std::string_view name, std::uint64_t rva, std::span<const std::byte> bytes,
    std::stop_token stop = {}, std::string_view hash = {}) noexcept;
void MemoryStatus(std::string_view reason) noexcept;
void Exception(std::string_view stage, const std::exception& error) noexcept;
}
