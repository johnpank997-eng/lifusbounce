#include "core/diagnostic_archive.hpp"
#include "core/handle.hpp"
#include <miniz.h>
#include <array>
#include <cstring>
#include <limits>

namespace base::diagnostics {
namespace {
constexpr std::string_view member = "diagnostic.jsonl";
constexpr std::uint64_t header_size = 30 + member.size();

struct Header {
    std::array<std::byte, 256> bytes{};
    std::size_t size{};

    void Number(std::uint64_t value, unsigned width = 2) noexcept {
        for (unsigned i = 0; i < width; ++i)
            bytes[size++] = std::byte((value >> (i * 8)) & 255);
    }

    void Name() noexcept {
        std::memcpy(bytes.data() + size, member.data(), member.size());
        size += member.size();
    }
};
}

struct Archive::Implementation {
    UniqueHandle file;
    std::unique_ptr<tdefl_compressor> compressor = std::make_unique<tdefl_compressor>();
    std::uint64_t position{}, uncompressed{};
    mz_ulong crc{};
    DWORD error{};
    std::uint16_t time{}, date{};

    bool Seek(std::uint64_t at) noexcept {
        LARGE_INTEGER offset{};
        offset.QuadPart = static_cast<LONGLONG>(at);
        if (SetFilePointerEx(file.Get(), offset, nullptr, FILE_BEGIN))
            return true;
        error = GetLastError();
        return false;
    }

    bool Write(const void* bytes, std::size_t size) noexcept {
        DWORD written{};
        const auto result = WriteFile(file.Get(), bytes, static_cast<DWORD>(size), &written, nullptr);
        if (!result || written != size) {
            error = result ? ERROR_WRITE_FAULT : GetLastError();
            return false;
        }
        position += written;
        return true;
    }

    DWORD Checkpoint() noexcept {
        if (!file)
            return error ? error : ERROR_INVALID_HANDLE;
        const auto end = position;
        if (end < header_size || end > UINT32_MAX - 256 || uncompressed > UINT32_MAX)
            return error = ERROR_FILE_TOO_LARGE;
        const auto compressed = end - header_size + 5;
        Header tail;
        tail.Number(1, 1);
        tail.Number(0);
        tail.Number(0xffff);
        tail.Number(0x08074b50, 4);
        tail.Number(crc, 4);
        tail.Number(compressed, 4);
        tail.Number(uncompressed, 4);
        const auto directory = end + tail.size;
        const auto begin = tail.size;
        tail.Number(0x02014b50, 4);
        tail.Number(20);
        tail.Number(20);
        tail.Number(8);
        tail.Number(8);
        tail.Number(time);
        tail.Number(date);
        tail.Number(crc, 4);
        tail.Number(compressed, 4);
        tail.Number(uncompressed, 4);
        tail.Number(member.size());
        tail.Number(0);
        tail.Number(0);
        tail.Number(0);
        tail.Number(0);
        tail.Number(0, 4);
        tail.Number(0, 4);
        tail.Name();
        const auto directory_size = tail.size - begin;
        tail.Number(0x06054b50, 4);
        tail.Number(0);
        tail.Number(0);
        tail.Number(1);
        tail.Number(1);
        tail.Number(directory_size, 4);
        tail.Number(directory, 4);
        tail.Number(0);
        if (!Write(tail.bytes.data(), tail.size))
            return error;
        if (!SetEndOfFile(file.Get()))
            return error = GetLastError();
        if (!Seek(end))
            return error;
        position = end;
        return ERROR_SUCCESS;
    }
};

Archive::Archive() = default;

Archive::~Archive() {
    Close();
}

DWORD Archive::Open(const std::wstring& path) {
    Close();
    const auto attributes = GetFileAttributesW(path.c_str());
    if (attributes != INVALID_FILE_ATTRIBUTES &&
        attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))
        return ERROR_ACCESS_DENIED;
    impl_ = std::make_unique<Implementation>();
    auto& state = *impl_;
    state.file.Reset(CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!state.file)
        return state.error = GetLastError();
    SYSTEMTIME now{};
    GetSystemTime(&now);
    state.time = static_cast<std::uint16_t>((now.wHour << 11) | (now.wMinute << 5) | (now.wSecond / 2));
    state.date = static_cast<std::uint16_t>(((now.wYear - 1980) << 9) | (now.wMonth << 5) | now.wDay);
    Header header;
    header.Number(0x04034b50, 4);
    header.Number(20);
    header.Number(8);
    header.Number(8);
    header.Number(state.time);
    header.Number(state.date);
    header.Number(0, 4);
    header.Number(0, 4);
    header.Number(0, 4);
    header.Number(member.size());
    header.Number(0);
    header.Name();
    if (!state.Write(header.bytes.data(), header.size)) {
        state.file.Reset();
        return state.error;
    }
    const auto status = tdefl_init(
        state.compressor.get(),
        [](const void* bytes, int size, void* context) -> mz_bool {
            return static_cast<Implementation*>(context)->Write(bytes, static_cast<std::size_t>(size));
        },
        &state, TDEFL_GREEDY_PARSING_FLAG | 1);
    if (status != TDEFL_STATUS_OKAY) {
        state.file.Reset();
        return state.error = ERROR_INVALID_DATA;
    }
    return Append({});
}

DWORD Archive::Append(std::string_view text) noexcept {
    if (!*this)
        return ERROR_INVALID_HANDLE;
    auto& state = *impl_;
    const auto status =
        tdefl_compress_buffer(state.compressor.get(), text.data(), text.size(), TDEFL_SYNC_FLUSH);
    if (status != TDEFL_STATUS_OKAY)
        return state.error ? state.error : ERROR_INVALID_DATA;
    state.crc = mz_crc32(state.crc, reinterpret_cast<const unsigned char*>(text.data()), text.size());
    state.uncompressed += text.size();
    return state.Checkpoint();
}

DWORD Archive::Flush() noexcept {
    if (!*this)
        return ERROR_SUCCESS;
    if (FlushFileBuffers(impl_->file.Get()))
        return ERROR_SUCCESS;
    return impl_->error = GetLastError();
}

DWORD Archive::Close() noexcept {
    const auto error = Flush();
    if (impl_)
        impl_->file.Reset();
    return error;
}

Archive::operator bool() const noexcept {
    return impl_ && static_cast<bool>(impl_->file);
}
}
