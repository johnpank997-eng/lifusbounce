#pragma once
#include "core/mem.hpp"
#include "sdk/locator.hpp"
#include "sdk/player.hpp"
#include "sdk/reload.hpp"
#include <memory>
#include <stop_token>
#include <string>

namespace base::sdk {
class Reader {
  public:
    Reader(const Memory& process, ModuleInfo module, IMAGE_NT_HEADERS64 header,
        locators::NativeDescriptor native);
    ~Reader();
    Reader(const Reader&) = delete;
    Reader& operator=(const Reader&) = delete;
    [[nodiscard]] std::shared_ptr<const Snapshot> Poll(std::stop_token stop);
    void Reload(ReloadTarget target);
    [[nodiscard]] const std::string& Status() const noexcept;
    [[nodiscard]] DWORD Error() const noexcept;
    [[nodiscard]] std::uint64_t Epoch() const noexcept;

  private:
    struct Implementation;
    std::unique_ptr<Implementation> impl_;
};
}
