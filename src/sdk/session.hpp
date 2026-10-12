#pragma once
#include "sdk/player.hpp"
#include "sdk/reload.hpp"
#include <windows.h>
#include <memory>
#include <optional>
#include <string>

namespace base::sdk {
[[nodiscard]] std::optional<DWORD> FindProcess();

struct SessionStatus {
    std::string message = "disabled";
    DWORD error = ERROR_SUCCESS;
    DWORD pid = 0;
    std::shared_ptr<const Snapshot> frame;
    float progress = 0.0f;
    bool running = false;
};

class Session {
  public:
    Session();
    ~Session();
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
    void SetEnabled(bool enabled);
    void Reload(ReloadTarget target);
    [[nodiscard]] SessionStatus Status() const;
    [[nodiscard]] std::optional<skeleton::Matrix> View(const SessionStatus& value);

  private:
    struct Implementation;
    std::unique_ptr<Implementation> impl_;
};
}
