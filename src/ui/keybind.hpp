#pragma once
#include <windows.h>
#include <algorithm>
#include <array>
#include <cctype>
#include <initializer_list>
#include <string>

namespace base {
class Keybind {
    std::array<int, 4> keys_{}, pending_{};
    unsigned count_{}, pending_count_{};
    bool capturing_{}, armed_{};

    static bool Down(int key) { return (GetAsyncKeyState(key) & 0x8000) != 0; }

    static bool Recordable(int key) {
        return key != VK_CANCEL && key != VK_SHIFT && key != VK_CONTROL && key != VK_MENU &&
            key != VK_INSERT && key != VK_END && key != VK_ESCAPE && key != VK_BACK;
    }

    static std::string Name(int key) {
        switch (key) {
        case VK_LBUTTON:
            return "lmb";
        case VK_RBUTTON:
            return "rmb";
        case VK_MBUTTON:
            return "mmb";
        case VK_XBUTTON1:
            return "mouse4";
        case VK_XBUTTON2:
            return "mouse5";
        case VK_LSHIFT:
            return "lshift";
        case VK_RSHIFT:
            return "rshift";
        case VK_LCONTROL:
            return "lctrl";
        case VK_RCONTROL:
            return "rctrl";
        case VK_LMENU:
            return "lalt";
        case VK_RMENU:
            return "ralt";
        }
        char label[64]{};
        unsigned scan = MapVirtualKeyA(key, MAPVK_VK_TO_VSC_EX);
        if (scan & 0xff00)
            scan = (scan & 0xff) | 0x100;
        if (!GetKeyNameTextA(static_cast<LONG>(scan << 16), label, sizeof(label)))
            return "key " + std::to_string(key);
        std::string result = label;
        std::transform(result.begin(), result.end(), result.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return result;
    }

  public:
    Keybind() = default;

    explicit Keybind(std::initializer_list<int> keys)
        : count_(static_cast<unsigned>(std::min(keys.size(), keys_.size()))) {
        std::copy_n(keys.begin(), count_, keys_.begin());
    }

    [[nodiscard]] bool Capturing() const { return capturing_; }

    void Begin() {
        capturing_ = true;
        armed_ = false;
        pending_count_ = 0;
    }

    void Cancel() {
        capturing_ = armed_ = false;
        pending_count_ = 0;
    }

    [[nodiscard]] bool Held() const {
        if (capturing_ || !count_)
            return false;
        for (unsigned i = 0; i < count_; ++i)
            if (!Down(keys_[i]))
                return false;
        return true;
    }

    void Poll() {
        if (!capturing_)
            return;
        if (armed_ && Down(VK_ESCAPE)) {
            Cancel();
            return;
        }
        if (armed_ && Down(VK_BACK)) {
            count_ = 0;
            Cancel();
            return;
        }
        bool any = false;
        for (int key = 1; key < 256; ++key) {
            if (!Recordable(key) || !Down(key))
                continue;
            any = true;
            if (armed_ && pending_count_ < pending_.size() &&
                std::find(pending_.begin(), pending_.begin() + pending_count_, key) ==
                    pending_.begin() + pending_count_)
                pending_[pending_count_++] = key;
        }

        if (!armed_) {
            armed_ = !any;
        } else if (!any && pending_count_) {
            keys_ = pending_;
            count_ = pending_count_;
            Cancel();
        }
    }

    [[nodiscard]] std::string Label() const {
        if (capturing_)
            return armed_ ? (pending_count_ ? "release to apply" : "press keys...") : "release mouse...";
        if (!count_)
            return "none";
        std::string result;
        for (unsigned i = 0; i < count_; ++i) {
            if (i)
                result += " + ";
            result += Name(keys_[i]);
        }
        return result;
    }
};
}
