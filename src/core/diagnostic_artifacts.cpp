#include "core/diagnostics_internal.hpp"
#include <compressapi.h>
#include <algorithm>
#include <mutex>
#include <vector>

namespace base::diagnostics {
namespace {
struct Compressor {
    COMPRESSOR_HANDLE handle{};

    Compressor() { CreateCompressor(COMPRESS_ALGORITHM_XPRESS_HUFF, nullptr, &handle); }

    ~Compressor() {
        if (handle)
            CloseCompressor(handle);
    }
};

std::string Base64(std::span<const std::byte> bytes) {
    constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((bytes.size() + 2) / 3 * 4);
    for (std::size_t i = 0; i < bytes.size(); i += 3) {
        const auto a = std::to_integer<unsigned>(bytes[i]);
        const auto b = i + 1 < bytes.size() ? std::to_integer<unsigned>(bytes[i + 1]) : 0;
        const auto c = i + 2 < bytes.size() ? std::to_integer<unsigned>(bytes[i + 2]) : 0;
        out += alphabet[a >> 2];
        out += alphabet[((a & 3) << 4) | (b >> 4)];
        out += i + 1 < bytes.size() ? alphabet[((b & 15) << 2) | (c >> 6)] : '=';
        out += i + 2 < bytes.size() ? alphabet[c & 63] : '=';
    }
    return out;
}
}

bool Artifact(std::string_view name, std::uint64_t rva, std::span<const std::byte> bytes,
    std::stop_token stop, std::string_view supplied_hash) noexcept {
    try {
        if (!Enabled())
            return false;
        static std::mutex mutex;
        const std::lock_guard lock(mutex);
        const auto hash = supplied_hash.empty() ? Sha256(bytes) : std::string(supplied_hash);
        if (hash.size() != 64)
            return false;
        const auto key = std::string(name) + ':' + Hex(rva) + ':' + hash;
        if (KnownArtifact(key))
            return EvidenceRecord("artifact_reference", {{"name", name}, {"id", key}, {"sha256", hash}});
        constexpr std::size_t chunk_size = 1024 * 1024;
        if (!EvidenceRecord("artifact_begin",
                {{"name", name}, {"id", key}, {"rva", Hex(rva)}, {"size", bytes.size()}, {"sha256", hash},
                    {"chunk_size", chunk_size}}))
            return false;
        Compressor compressor;
        std::vector<std::byte> compressed;
        std::size_t offset{};
        unsigned chunks{};
        DWORD error{};
        while (offset < bytes.size() && !stop.stop_requested()) {
            const auto part = bytes.subspan(offset, std::min(chunk_size, bytes.size() - offset));
            auto encoded = part;
            std::string_view codec = "raw";
            SIZE_T required{};
            if (compressor.handle &&
                !Compress(compressor.handle, part.data(), part.size(), nullptr, 0, &required) &&
                GetLastError() == ERROR_INSUFFICIENT_BUFFER && required <= chunk_size * 2) {
                compressed.resize(required);
                SIZE_T written{};
                if (Compress(compressor.handle, part.data(), part.size(), compressed.data(),
                        compressed.size(), &written) &&
                    written < part.size()) {
                    encoded = std::span(compressed).first(written);
                    codec = "xpress_huffman";
                }
            }
            const auto payload = Base64(encoded);
            if (!EvidenceRecord("artifact_chunk",
                    {{"id", key}, {"offset", offset}, {"size", part.size()}, {"codec", codec},
                        {"sha256", Sha256(part)}},
                    payload)) {
                error = Error() ? Error() : ERROR_DISK_FULL;
                break;
            }
            offset += part.size();
            ++chunks;
        }
        const bool complete = offset == bytes.size() && !stop.stop_requested();
        const auto finished = EvidenceRecord("artifact_end",
            {{"id", key}, {"complete", complete}, {"captured", offset}, {"chunks", chunks},
                {"cancelled", stop.stop_requested()}, {"win32", error}});
        if (complete && finished)
            RememberArtifact(key);
        return complete && finished;
    } catch (const std::exception& error) {
        Exception("evidence capture", error);
    } catch (...) {
        Write("evidence_exception", {{"name", name}, {"message", "unknown exception"}});
    }
    return false;
}
}
