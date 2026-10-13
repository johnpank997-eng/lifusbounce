#include "sdk/session.hpp"
#include "sdk/reader.hpp"
#include "sdk/diagnostics.hpp"
#include "core/diagnostics.hpp"
#include <mutex>
#include <thread>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <exception>
#include <limits>
#include <new>
#include <system_error>
#include <vector>
#include <utility>

namespace base::sdk {
namespace {
using RuntimeFunction = locators::FunctionRecord;

bool InImage(std::uint32_t rva, std::size_t size, std::uint32_t image_size) {
    return rva < image_size && size <= image_size - rva;
}

bool GameName(const std::wstring& name) {
    return _wcsicmp(name.c_str(), L"rainbowsix.exe") == 0 ||
        _wcsicmp(name.c_str(), L"rainbowsix_vulkan.exe") == 0;
}

}

struct Session::Implementation {
    SessionStatus Status() const;
    void Publish(SessionStatus value, std::stop_token stop);
    void SetEnabled(bool enabled);
    void Reload(ReloadTarget target);
    void Scan(std::stop_token stop);
    mutable std::mutex mutex_;
    SessionStatus status_;
    unsigned pending_reload_ = 0;
    bool worker_running_ = false;
    DWORD target_pid_ = 0;
    Memory camera_process;
    std::jthread worker_;
    int logged_progress_ = -1;
    std::chrono::steady_clock::time_point logged_at_{};
};

std::optional<DWORD> FindProcess() {
    DWORD error{};
    const auto list = Processes(error);
    if (error)
        return std::nullopt;
    const auto matches = [](const ProcessInfo& value) { return GameName(value.name); };
    if (std::count_if(list.begin(), list.end(), matches) != 1)
        return 0;
    return std::find_if(list.begin(), list.end(), matches)->pid;
}

SessionStatus Session::Implementation::Status() const {
    const std::lock_guard lock(mutex_);
    auto value = status_;
    value.running = worker_running_;
    return value;
}

void Session::Implementation::Publish(SessionStatus value, std::stop_token stop) {
    const std::lock_guard lock(mutex_);
    if (!stop.stop_requested() && !pending_reload_) {
        value.pid = target_pid_;
        value.progress = std::max(status_.progress, std::clamp(value.progress, 0.0f, 1.0f));
        const auto now = std::chrono::steady_clock::now();
        const auto percent = static_cast<int>(value.progress * 100.0f);
        const bool changed = value.waiting != status_.waiting || value.error != status_.error ||
            (value.progress < 0.92f && value.message != status_.message) ||
            (value.progress >= 1.0f && logged_progress_ < 100);
        diagnostics::Phase(value.message, value.progress);
        if ((changed &&
                (value.progress < 0.92f || value.waiting != status_.waiting ||
                    now - logged_at_ >= std::chrono::milliseconds(250))) ||
            percent >= logged_progress_ + 5 || now - logged_at_ >= std::chrono::seconds(5)) {
            diagnostics::Write("session_status",
                {{"message", value.message}, {"win32", value.error},
                    {"progress_percent", value.progress * 100.0f}, {"waiting", value.waiting},
                    {"has_frame", value.frame != nullptr},
                    {"players", value.frame ? value.frame->players : 0u},
                    {"initialized", value.frame ? value.frame->initialized : 0u},
                    {"skeletons", value.frame ? value.frame->entities.size() : 0u}});
            logged_at_ = now;
            logged_progress_ = percent;
        }
        status_ = std::move(value);
    }
}

void Session::Implementation::SetEnabled(bool enabled) {
    diagnostics::Initialize();
    diagnostics::Write("session_enabled", {{"enabled", enabled}});
    worker_.request_stop();
    if (worker_.joinable())
        worker_.join();
    target_pid_ = 0;
    camera_process.Detach();
    {
        const std::lock_guard lock(mutex_);
        status_ = {};
        pending_reload_ = 0;
        worker_running_ = enabled;
        logged_progress_ = -1;
        logged_at_ = {};
    }
    if (!enabled)
        return;
    worker_ = std::jthread([this](std::stop_token stop) {
        try {
            Scan(stop);
        } catch (const std::system_error& error) {
            diagnostics::Exception("session scan", error);
            Publish({error.what(), static_cast<DWORD>(error.code().value())}, stop);
        } catch (const std::bad_alloc& error) {
            diagnostics::Exception("session scan", error);
            Publish({"not enough memory for the locator scan", ERROR_NOT_ENOUGH_MEMORY}, stop);
        } catch (const std::exception& error) {
            diagnostics::Exception("session scan", error);
            Publish({"locator scan threw an exception; see diagnostic log", ERROR_INVALID_DATA}, stop);
        }
        const auto final_status = Status();
        diagnostics::Write("scan_finished",
            {{"cancelled", stop.stop_requested()}, {"message", final_status.message},
                {"win32", final_status.error}, {"progress_percent", final_status.progress * 100.0f}});
        const std::lock_guard lock(mutex_);
        worker_running_ = false;
    });
}

void Session::Implementation::Reload(ReloadTarget target) {
    diagnostics::Write("reload_requested", {{"target", static_cast<unsigned>(target)}});
    if (target != ReloadTarget::all) {
        const std::lock_guard lock(mutex_);
        if (worker_running_ && status_.progress >= 0.92f) {
            pending_reload_ |= static_cast<unsigned>(target);
            status_.frame.reset();
            status_.message = "reload queued";
            status_.error = ERROR_SUCCESS;
            status_.progress = 0.92f;
            status_.waiting = false;
            return;
        }
    }

    SetEnabled(true);
}

void Session::Implementation::Scan(std::stop_token stop) {
    Publish({"looking for the game"}, stop);
    DWORD error = ERROR_SUCCESS;
    auto list = Processes(error);
    if (error) {
        Publish({"cannot enumerate processes", error}, stop);
        return;
    }
    const auto target =
        std::find_if(list.begin(), list.end(), [](const ProcessInfo& p) { return GameName(p.name); });
    if (target == list.end()) {
        Publish({"game is not running"}, stop);
        return;
    }
    if (std::count_if(list.begin(), list.end(), [](const ProcessInfo& p) { return GameName(p.name); }) != 1) {
        Publish({"more than one game process"}, stop);
        return;
    }
    Memory process;
    if ((error = process.Attach(target->pid)) != ERROR_SUCCESS) {
        Publish({"cannot read the game process", error}, stop);
        return;
    }
    diagnostics::Write("game_attached", {{"pid", target->pid}});
    target_pid_ = target->pid;
    Publish({"reading the game module", ERROR_SUCCESS, target_pid_, {}, 0.05f}, stop);
    if (process.Is64Bit(error) != std::optional<bool>(true)) {
        Publish({"an x64 game process is required", error}, stop);
        return;
    }
    const auto modules = process.Modules(error);
    if (error) {
        Publish({"cannot read the game module", error}, stop);
        return;
    }
    const auto module = std::find_if(modules.begin(), modules.end(),
        [&](const ModuleInfo& m) { return _wcsicmp(m.name.c_str(), target->name.c_str()) == 0; });
    if (module == modules.end()) {
        Publish({"game module was not found"}, stop);
        return;
    }
    if (module->size > std::numeric_limits<std::uintptr_t>::max() - module->address) {
        Publish({"invalid game image range"}, stop);
        return;
    }
    const auto dos = process.Read<IMAGE_DOS_HEADER>(module->address, &error);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
        static_cast<std::size_t>(dos->e_lfanew) > module->size ||
        sizeof(IMAGE_NT_HEADERS64) > module->size - static_cast<std::size_t>(dos->e_lfanew)) {
        Publish({"cannot read the game image header", error}, stop);
        return;
    }
    const auto nt = process.Read<IMAGE_NT_HEADERS64>(module->address + dos->e_lfanew, &error);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt->OptionalHeader.SizeOfImage > module->size ||
        nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
        Publish({"unsupported game image header", error}, stop);
        return;
    }
    const auto& header = nt->OptionalHeader;
    diagnostics::Write("game_image",
        {{"pid", target->pid}, {"image_size", header.SizeOfImage},
            {"pe_timestamp", nt->FileHeader.TimeDateStamp}, {"code_rva", header.BaseOfCode},
            {"code_size", header.SizeOfCode}, {"machine", nt->FileHeader.Machine},
            {"sections", nt->FileHeader.NumberOfSections}});
    const auto directory = header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!InImage(directory.VirtualAddress, directory.Size, header.SizeOfImage) || !directory.Size ||
        directory.Size % sizeof(RuntimeFunction) || directory.Size > 32 * 1024 * 1024 || !header.SizeOfCode ||
        header.SizeOfCode > 512 * 1024 * 1024 ||
        !InImage(header.BaseOfCode, header.SizeOfCode, header.SizeOfImage)) {
        Publish({"unsupported game code or function table"}, stop);
        return;
    }
    std::vector<RuntimeFunction> functions(directory.Size / sizeof(RuntimeFunction));
    const auto table_read = process.ReadBytes(
        module->address + directory.VirtualAddress, std::as_writable_bytes(std::span(functions)));
    if (!table_read.Complete()) {
        Publish({"cannot read the game function table", table_read.error}, stop);
        return;
    }
    std::uint32_t previous = 0;
    for (std::size_t i = 0; i < functions.size(); ++i) {
        const auto& f = functions[i];
        if (f.begin >= f.end || f.end > header.SizeOfImage || (i && f.begin <= previous)) {
            Publish({"invalid game function table"}, stop);
            return;
        }
        previous = f.begin;
    }
    Publish({"discovering native pointer and metadata paths", ERROR_SUCCESS, target_pid_, {}, 0.10f}, stop);
    locators::NativeDescriptor native;
    DiscoveryDiagnostics discovery(module->address);
    {
        std::vector<std::byte> code(header.SizeOfCode);
        for (std::size_t offset = 0; offset < code.size();) {
            if (stop.stop_requested())
                return;
            const auto size = std::min<std::size_t>(0x400000, code.size() - offset);
            const auto got = process.ReadBytes(
                module->address + header.BaseOfCode + offset, std::span(code).subspan(offset, size));
            if (!got.Complete()) {
                diagnostics::Write("native_code_read_error",
                    {{"rva", diagnostics::Hex(header.BaseOfCode + offset)}, {"requested", size},
                        {"transferred", got.transferred}, {"win32", got.error}});
                diagnostics::Artifact("partial_game_code", header.BaseOfCode,
                    std::span(code).first(offset + got.transferred), stop);
                Publish({"cannot read native locator code", got.error}, stop);
                return;
            }
            offset += size;
            const float progress =
                0.10f + 0.50f * static_cast<float>(offset) / static_cast<float>(code.size());
            Publish({"reading native locator code", ERROR_SUCCESS, target_pid_, {}, progress}, stop);
        }
        diagnostics::Phase("fingerprinting native code", 0.60f);
        const auto code_hash = diagnostics::Sha256(code);
        const auto functions_hash = diagnostics::Sha256(std::as_bytes(std::span(functions)));
        diagnostics::Write("build_fingerprint",
            {{"code_sha256", code_hash}, {"functions_sha256", functions_hash},
                {"function_records", functions.size()}, {"code_rva", header.BaseOfCode},
                {"code_size", header.SizeOfCode}, {"functions_rva", directory.VirtualAddress},
                {"functions_size", directory.Size}});
        ReportImage(process, *module, *nt, code, functions, code_hash, stop);
        if (stop.stop_requested())
            return;
        try {
            native = locators::Discover(
                code, header.BaseOfCode, module->address, functions, stop,
                [&](std::size_t completed, std::size_t total) {
                    const float progress = 0.60f +
                        0.30f * static_cast<float>(completed) /
                            static_cast<float>(std::max<std::size_t>(total, 1));
                    Publish({"discovering native paths", ERROR_SUCCESS, target_pid_, {}, progress}, stop);
                },
                [&](std::string_view role, const locators::FunctionRecord& function,
                    std::span<const std::byte> bytes, const Emulator::Program* decoded,
                    std::size_t accepted) { discovery.Observe(role, function, bytes, decoded, accepted); },
                [&](std::string_view stage, std::size_t index, const locators::FunctionRecord& function) {
                    discovery.Enter(stage, index, function);
                },
                [&](std::string_view rule, std::uint64_t instruction, std::uint64_t observed) {
                    discovery.Validation(rule, instruction, observed);
                });
        } catch (const std::exception& error) {
            discovery.Failure(error);
            throw;
        }
        discovery.Report();
        diagnostics::Phase("selected character discovery", 0.90f);
        if (!stop.stop_requested() && nt->FileHeader.NumberOfSections &&
            nt->FileHeader.NumberOfSections <= 96) {
            std::vector<IMAGE_SECTION_HEADER> sections(nt->FileHeader.NumberOfSections);
            const auto address = module->address + dos->e_lfanew + 24 + nt->FileHeader.SizeOfOptionalHeader;
            if (process.ReadBytes(address, std::as_writable_bytes(std::span(sections))).Complete())
                for (const auto& section : sections)
                    if (std::memcmp(section.Name, ".rdata", 6) == 0 && section.Misc.VirtualSize &&
                        section.Misc.VirtualSize <= 32 * 1024 * 1024 &&
                        section.VirtualAddress < header.SizeOfImage &&
                        section.Misc.VirtualSize <= header.SizeOfImage - section.VirtualAddress) {
                        std::vector<std::byte> symbols(section.Misc.VirtualSize);
                        const auto read =
                            process.ReadBytes(module->address + section.VirtualAddress, symbols);
                        if (read.Complete())
                            native.selected_operator =
                                locators::DiscoverOperatorSelection(code, header.BaseOfCode, module->address,
                                    functions, symbols, section.VirtualAddress);
                        else
                            diagnostics::Write("optional_section_failed",
                                {{"role", "selected character"}, {"win32", read.error},
                                    {"transferred", read.transferred}});
                    }
        }
    }
    if (stop.stop_requested())
        return;
    diagnostics::Phase("recording native descriptors", 0.90f);
    ReportNative(native, module->address);
    const char* missing = native.roots.empty()          ? "roots"
        : native.roots.size() != native.contexts.size() ? "thread contexts"
        : native.cameras.empty()                        ? "camera"
        : native.metadata.empty()                       ? "component metadata"
        : native.managers.empty()                       ? "entity manager"
        : native.arrays.empty()                         ? "entity array"
        : native.poses.empty()                          ? "poses"
        : native.rigs.empty()                           ? "rig lookup"
                                                        : nullptr;
    if (missing) {
        diagnostics::Write("missing_prerequisite", {{"role", missing}});
        Publish({std::string("this build needs a new ") + missing + " path", ERROR_NOT_SUPPORTED}, stop);
        return;
    }
    Reader reader(process, *module, *nt, std::move(native));
    Publish({"initializing skeleton data", ERROR_SUCCESS, target_pid_, {}, 0.92f}, stop);

    UniqueHandle timer(CreateWaitableTimerExW(
        nullptr, nullptr, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_MODIFY_STATE | SYNCHRONIZE));
    if (!timer)
        timer.Reset(CreateWaitableTimerExW(nullptr, nullptr, 0, TIMER_MODIFY_STATE | SYNCHRONIZE));
    auto waiting_since = std::chrono::steady_clock::now();
    auto reported_at = waiting_since - std::chrono::seconds(5);
    auto layouts_at = waiting_since - std::chrono::seconds(30);
    while (!stop.stop_requested()) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(8);
        unsigned reload = 0;
        {
            const std::lock_guard lock(mutex_);
            reload = std::exchange(pending_reload_, 0u);
        }
        if (reload) {
            reader.Reload(static_cast<ReloadTarget>(reload));
            waiting_since = std::chrono::steady_clock::now();
        }
        const auto alive = process.Read<std::uint16_t>(module->address);
        if (!alive || *alive != IMAGE_DOS_SIGNATURE) {
            target_pid_ = 0;
            Publish({"game closed"}, stop);
            return;
        }
        auto frame = reader.Poll(stop);
        if (!frame && !stop.stop_requested())
            frame = reader.Poll(stop);
        const bool ready = frame && (!frame->players || frame->initialized);
        if (ready)
            waiting_since = std::chrono::steady_clock::now();
        const bool waiting =
            !ready && std::chrono::steady_clock::now() - waiting_since >= std::chrono::seconds(20);
        const auto report_now = std::chrono::steady_clock::now();
        if (report_now - reported_at >= std::chrono::seconds(5)) {
            const auto layouts = report_now - layouts_at >= std::chrono::seconds(30);
            reader.ReportDiagnostics(layouts);
            if (layouts)
                layouts_at = report_now;
            reported_at = report_now;
        }
        Publish({reader.Status(), reader.Error(), target_pid_, std::move(frame), ready ? 1.0f : 0.92f, false,
                    waiting},
            stop);
        const auto remaining = deadline - std::chrono::steady_clock::now();
        if (!stop.stop_requested() && remaining > std::chrono::steady_clock::duration::zero()) {
            LARGE_INTEGER due{};
            due.QuadPart = -std::max<LONGLONG>(
                1, std::chrono::duration_cast<std::chrono::nanoseconds>(remaining).count() / 100);
            if (timer && SetWaitableTimer(timer.Get(), &due, 0, nullptr, nullptr, FALSE))
                WaitForSingleObject(timer.Get(), 10);
            else
                Sleep(1);
        }
    }
}

Session::Session() : impl_(std::make_unique<Implementation>()) {}

Session::~Session() = default;

void Session::SetEnabled(bool enabled) {
    impl_->SetEnabled(enabled);
}

void Session::Reload(ReloadTarget target) {
    impl_->Reload(target);
}

SessionStatus Session::Status() const {
    return impl_->Status();
}

std::optional<skeleton::Matrix> Session::View(const SessionStatus& value) {
    if (!value.pid || !value.frame)
        return std::nullopt;
    auto& process = impl_->camera_process;
    if (process.Pid() != value.pid && process.Attach(value.pid) != ERROR_SUCCESS) {
        process.Detach();
        return std::nullopt;
    }
    return process.Read<skeleton::Matrix>(value.frame->view_address);
}
}
