#pragma once
#include <windows.h>
#include <memory>
#include <string>
#include <string_view>

namespace base::diagnostics {
class Archive {
  public:
    Archive();
    ~Archive();
    DWORD Open(const std::wstring& path);
    DWORD Append(std::string_view text) noexcept;
    DWORD Flush() noexcept;
    DWORD Close() noexcept;
    explicit operator bool() const noexcept;

  private:
    struct Implementation;
    std::unique_ptr<Implementation> impl_;
};
}
