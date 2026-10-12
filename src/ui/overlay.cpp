#include "ui/overlay_internal.hpp"
#include "ui/overlay.hpp"
#include "sdk/session.hpp"
#include "sdk/aim.hpp"
#include "ui/gfx.hpp"
#include "ui/operator_badges.hpp"
#include "ui/theme.hpp"
#include "ui/keybind.hpp"
#include "ui/draw.hpp"
#include "ui/frame_pacing.hpp"
#include <imgui.h>
#include <imgui_impl_win32.h>
#include <imgui_impl_dx11.h>
#include <chrono>
#include <array>
#include <string>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <cstdio>
#include <unordered_map>
#include <windowsx.h>
#include "resource.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

namespace base {
int RunOverlay(HINSTANCE instance) {
    Interaction input;
    WNDCLASSEXW cls{sizeof(cls)};
    cls.lpfnWndProc = WindowProc;
    cls.hInstance = instance;
    cls.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    cls.lpszClassName = L"lifus";
    if (!RegisterClassExW(&cls)) {
        MessageBoxW(nullptr, L"could not register the overlay window.", L"lifusbounce - startup failed",
            MB_OK | MB_ICONERROR);
        return 1;
    }
    HWND window = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
        cls.lpszClassName, L"lifusbounce", WS_POPUP, 0, 0, 480, 320, nullptr, nullptr, instance, &input);
    if (!window) {
        UnregisterClassW(cls.lpszClassName, instance);
        MessageBoxW(nullptr, L"could not create the overlay window.", L"lifusbounce - startup failed",
            MB_OK | MB_ICONERROR);
        return 1;
    }
    input.drawing = window;

    input.panel =
        CreateWindowExW(WS_EX_TOPMOST | WS_EX_NOREDIRECTIONBITMAP | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
            cls.lpszClassName, L"lifusbounce controls", WS_POPUP, 20, 20, (int)theme::panel_width,
            (int)theme::panel_height, nullptr, nullptr, instance, &input);
    if (!input.panel || !TransparentBacking(window, 480, 320, {0, 0})) {
        if (input.panel)
            DestroyWindow(input.panel);
        DestroyWindow(window);
        UnregisterClassW(cls.lpszClassName, instance);
        MessageBoxW(nullptr, L"could not create the overlay surfaces.", L"lifusbounce - startup failed",
            MB_OK | MB_ICONERROR);
        return 1;
    }

    Gfx renderer;
    OperatorBadges badges;
    if (!renderer.Init(window, input.panel) || !badges.Init(instance, renderer.device.Get())) {
        DestroyWindow(input.panel);
        DestroyWindow(window);
        UnregisterClassW(cls.lpszClassName, instance);
        MessageBoxW(nullptr, L"could not initialize Direct3D and desktop composition.",
            L"lifusbounce - startup failed", MB_OK | MB_ICONERROR);
        return 1;
    }
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::GetIO().IniFilename = nullptr;

    ImGui::GetIO().ConfigFlags |= ImGuiConfigFlags_NoMouseCursorChange;

    {
        const HRSRC res = FindResourceW(instance, MAKEINTRESOURCEW(IDR_FONT_VOLTE), RT_RCDATA);
        const HGLOBAL mem = res ? LoadResource(instance, res) : nullptr;
        const void* data = mem ? LockResource(mem) : nullptr;
        const DWORD size = res ? SizeofResource(instance, res) : 0;
        if (data && size > 0) {
            ImFontConfig cfg{};
            cfg.FontDataOwnedByAtlas = false;
            cfg.OversampleH = 3;
            cfg.OversampleV = 2;
            cfg.PixelSnapH = false;
            ImGui::GetIO().Fonts->AddFontFromMemoryTTF(
                const_cast<void*>(data), static_cast<int>(size), 14.0f, &cfg);
        }
    }

    theme::Apply();
    const bool platform_ready = ImGui_ImplWin32_Init(input.panel);
    const bool renderer_ready =
        platform_ready && ImGui_ImplDX11_Init(renderer.device.Get(), renderer.context.Get());
    if (!renderer_ready) {
        if (platform_ready)
            ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
        DestroyWindow(input.panel);
        DestroyWindow(window);
        UnregisterClassW(cls.lpszClassName, instance);
        MessageBoxW(nullptr, L"could not initialize the menu renderer.", L"lifusbounce - startup failed",
            MB_OK | MB_ICONERROR);
        return 1;
    }
    bool enabled = true, done = false, occluded = false;
    bool head_circle = true;
    bool username_esp = true;
    bool operator_esp = true;
    bool health_esp = true;
    bool health_number_esp = false;
    bool weapon_esp = false;
    bool defuser_esp = true;
    bool box_esp = true;
    bool foot_bones = true;
    bool finger_bones = true;
    bool esp_team_check = true;
    bool aim_team_check = true;
    int menu_tab = 0;
    int previous_tab = 0;
    float content_alpha = 1.0f;
    sdk::aim::Settings aim_settings;
    sdk::aim::Controller aiming;
    Keybind aim_key{VK_RBUTTON};
    float line_thickness = 1.0f;
    float fov_thickness = 1.0f;
    const auto default_fov_color = ImGui::ColorConvertU32ToFloat4(theme::accent);
    float fov_color[3] = {default_fov_color.x, default_fov_color.y, default_fov_color.z};
    float skeleton_color[3] = {1.0f, 1.0f, 1.0f};
    float head_color[3] = {1.0f, 1.0f, 1.0f};
    float username_color[3] = {1.0f, 1.0f, 1.0f};
    float weapon_color[3] = {0.8f, 0.1f, 0.1f};
    float box_color[3] = {0.0f, 0.0f, 0.0f};
    DisplayCache display;
    std::optional<sdk::skeleton::Matrix> cached_view;
    std::chrono::steady_clock::time_point cached_view_time{};
    sdk::Session game;
    GameTarget target;
    DWORD reader_pid{};
    bool reader_enabled = false;
    bool insert_down = false, end_down = false;
    bool hud_ready = false;
    std::string hud_text = "loading...";
    int exit_code = 0;
    bool scene_cleared = false, menu_cleared = false;
    ImDrawData scene_data, menu_data;
    while (!done) {
        MSG message{};
        while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
            if (message.message == WM_QUIT)
                done = true;
        }
        if (done)
            break;
        target.Update();
        if (target.closed)
            break;
        const bool pid_changed = reader_pid != target.pid;
        if (pid_changed) {
            hud_ready = false;
            input.loading_menu = false;
            hud_text = "loading...";
            aiming.Reset();
            input.Hide();
            cached_view.reset();
            display.Clear();
            scene_cleared = menu_cleared = false;
            reader_pid = target.pid;
            input.game_pid = reader_pid;
        }

        const bool want_reader = reader_pid != 0;
        if (pid_changed || reader_enabled != want_reader) {
            game.SetEnabled(want_reader);
            reader_enabled = want_reader;
            display.Clear();
            cached_view.reset();
        }
        if (input.game != target.window) {
            input.Hide();
            input.game = target.window;
        }
        const bool active = input.ForegroundGame();
        if (!active || !input.menu || input.loading)
            aim_key.Cancel();
        else
            aim_key.Poll();
        if (!active || input.menu || !aim_key.Held())
            aiming.Reset();
        const bool insert = (GetAsyncKeyState(VK_INSERT) & 0x8000) != 0;
        const bool end = (GetAsyncKeyState(VK_END) & 0x8000) != 0;
        if (active && !aim_key.Capturing() && insert && !insert_down) {
            if (input.loading && !input.loading_menu) {
                input.loading_menu = true;
                input.menu = true;
                menu_tab = 2;
            } else
                input.menu = !input.menu;
            if (input.menu) {
                ClipCursor(nullptr);
            } else {
                input.ReleaseInput();
            }
        }
        if (active && !aim_key.Capturing() && end && !end_down)
            done = true;
        insert_down = insert;
        end_down = end;
        if (done)
            break;
        auto status = game.Status();
        hud_ready = hud_ready || status.progress >= 1.0f;
        input.loading = !hud_ready;
        const bool game_active = input.ForegroundGame();
        RECT client{};
        POINT origin{};
        if (!game_active || !GetClientRect(input.game, &client) || !ClientToScreen(input.game, &origin) ||
            client.right <= 0 || client.bottom <= 0) {
            if (IsWindowVisible(window) || IsWindowVisible(input.panel))
                input.Hide();
            Sleep(10);
            continue;
        }
        input.SyncInput();
        RECT current{};
        GetWindowRect(window, &current);
        const bool resized =
            current.right - current.left != client.right || current.bottom - current.top != client.bottom;
        if (resized && !TransparentBacking(window, client.right, client.bottom, origin)) {
            exit_code = 1;
            break;
        }
        if (resized)
            scene_cleared = false;
        if (resized || current.left != origin.x || current.top != origin.y)
            SetWindowPos(
                window, HWND_TOPMOST, origin.x, origin.y, client.right, client.bottom, SWP_NOACTIVATE);
        if (input.menu)
            ClipCursor(nullptr);
        const float max_x = std::max(0.0f, static_cast<float>(client.right) - theme::panel_width);
        const float max_y = std::max(0.0f, static_cast<float>(client.bottom) - theme::panel_height);
        {
            const int pw = (int)theme::panel_width, ph = (int)theme::panel_height;
            if (!input.panel_centered) {
                input.panel_x = max_x * 0.5f;
                input.panel_y = max_y * 0.5f;
                input.panel_centered = true;
            }
            input.panel_x = std::clamp(input.panel_x, 0.0f, max_x);
            input.panel_y = std::clamp(input.panel_y, 0.0f, max_y);
            const RECT want{origin.x + static_cast<LONG>(input.panel_x),
                origin.y + static_cast<LONG>(input.panel_y), std::min<LONG>(pw, client.right),
                std::min<LONG>(ph, client.bottom)};
            if (std::memcmp(&want, &input.applied, sizeof(RECT)) != 0) {
                SetWindowPos(
                    input.panel, HWND_TOPMOST, want.left, want.top, want.right, want.bottom, SWP_NOACTIVATE);
                input.applied = want;
            }
        }
        const bool menu_visible =
            (!input.loading || input.loading_menu) && (input.menu || input.menu_alpha > 0.01f);
        if (menu_visible && !IsWindowVisible(input.panel))
            ShowWindow(input.panel, SW_SHOWNOACTIVATE);
        else if (!menu_visible && IsWindowVisible(input.panel))
            ShowWindow(input.panel, SW_HIDE);
        if (menu_visible)
            SetWindowPos(input.panel, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOSIZE);
        if (!IsWindowVisible(window))
            ShowWindow(window, SW_SHOWNOACTIVATE);
        if (IsIconic(window)) {
            WaitMessage();
            continue;
        }
        if (occluded && renderer.swap_chain->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED) {
            Sleep(10);
            continue;
        }
        if (!renderer.Resize(static_cast<UINT>(client.right), static_cast<UINT>(client.bottom))) {
            exit_code = 1;
            break;
        }
        const auto ready = renderer.WaitFrame(input.game);
        if (ready == WAIT_FAILED) {
            exit_code = 1;
            break;
        }
        if (ready != WAIT_OBJECT_0)
            continue;
        if (!input.ForegroundGame()) {
            input.Hide();
            continue;
        }

        const auto frame_started = std::chrono::steady_clock::now();

        status = game.Status();

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::GetIO().DisplaySize = {static_cast<float>(client.right), static_cast<float>(client.bottom)};
        input.PollMouse();
        ImGui::NewFrame();

        const float menu_target = input.menu && (!input.loading || input.loading_menu) ? 1.0f : 0.0f;
        input.menu_alpha += (menu_target - input.menu_alpha) *
            (1.0f - std::exp(-22.0f * std::min(ImGui::GetIO().DeltaTime, 0.05f)));
        if (std::abs(menu_target - input.menu_alpha) < 0.001f)
            input.menu_alpha = menu_target;
        if (input.menu_alpha > 0.01f) {
            const float saved_alpha = ImGui::GetStyle().Alpha;
            ImGui::GetStyle().Alpha = input.menu_alpha;
            ui_alpha = input.menu_alpha;

            ImGui::SetNextWindowPos({input.panel_x, input.panel_y}, ImGuiCond_Always);
            ImGui::SetNextWindowSize({theme::panel_width, theme::panel_height}, ImGuiCond_Always);
            if (ImGui::Begin("##menu", nullptr,
                    ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                        (input.menu ? 0 : ImGuiWindowFlags_NoInputs))) {
                const ImVec2 wpos = ImGui::GetWindowPos();
                ImGui::SetCursorPos({0.0f, 0.0f});
                ImGui::InvisibleButton("##drag", {theme::panel_width - 29, theme::header_height});
                if (ImGui::IsItemActive()) {
                    const ImVec2 delta = ImGui::GetIO().MouseDelta;
                    input.panel_x = std::clamp(input.panel_x + delta.x, 0.0f, max_x);
                    input.panel_y = std::clamp(input.panel_y + delta.y, 0.0f, max_y);
                }

                if (MenuFrame(wpos, menu_tab)) {
                    input.menu = false;
                    aim_key.Cancel();
                }

                if (previous_tab != menu_tab) {
                    previous_tab = menu_tab;
                    content_alpha = 0.0f;
                }
                content_alpha += (1.0f - content_alpha) *
                    (1.0f - std::exp(-9.0f * std::min(ImGui::GetIO().DeltaTime, 0.05f)));
                ImGui::SetCursorPos(
                    {theme::sidebar_width + theme::pad, theme::content_top + 3.0f * (1.0f - content_alpha)});
                ImGui::BeginChild("##content", {theme::content_width, theme::content_height}, false,
                    ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoScrollbar);

                ui_alpha = input.menu_alpha * content_alpha;
                ImGui::GetStyle().Alpha = ui_alpha;

                if (menu_tab == 0) {
                    ToggleRow("username", &username_esp, username_color);
                    ToggleRow("operator", &operator_esp, nullptr);
                    ToggleRow("health", &health_esp, nullptr);
                    ToggleRow("health number", &health_number_esp, nullptr);
                    ToggleRow("weapon", &weapon_esp, weapon_color);
                    ToggleRow("defuser", &defuser_esp, nullptr);
                    ToggleRow("box", &box_esp, box_color);
                    ToggleRow("skeleton", &enabled, skeleton_color);
                    ToggleRow("head circle", &head_circle, head_color);
                    ToggleRow("foot bones", &foot_bones, nullptr);
                    ToggleRow("finger bones", &finger_bones, nullptr);
                    ToggleRow("team check", &esp_team_check, nullptr);
                    ImGui::Dummy({0.0f, 8.0f});
                    CustomSlider("line thickness", &line_thickness, 1.0f, 3.0f);
                } else if (menu_tab == 1) {
                    ToggleRow("aimbot", &aim_settings.enabled, nullptr);
                    ToggleRow("show fov", &aim_settings.show_fov, fov_color);
                    ToggleRow("team check", &aim_team_check, nullptr);
                    constexpr const char* names[]{"head", "closest"};
                    const auto bone_row = ImGui::GetCursorScreenPos();
                    if (ChoiceRow("target bone", names[static_cast<unsigned>(aim_settings.bone)]))
                        ImGui::OpenPopup("##target_bone");
                    ImGui::SetNextWindowPos({bone_row.x + theme::content_width - theme::value_width,
                        bone_row.y + theme::row_height});
                    ImGui::SetNextWindowSize({theme::value_width, 0});
                    const float popup_alpha =
                        Animate("bone_popup", ImGui::IsPopupOpen("##target_bone") ? 1.0f : 0.0f, 22.0f);
                    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, {6, 6});
                    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, ui_alpha * popup_alpha);
                    if (ImGui::BeginPopup("##target_bone")) {
                        for (unsigned option = 0; option < std::size(names); ++option) {
                            if (ImGui::Selectable(
                                    names[option], static_cast<unsigned>(aim_settings.bone) == option)) {
                                aim_settings.bone = static_cast<sdk::aim::TargetBone>(option);
                                aiming.Reset();
                            }
                        }
                        ImGui::EndPopup();
                    }
                    ImGui::PopStyleVar(2);
                    const auto binding_label = aim_key.Label();
                    ChoiceRow("aim key", binding_label.c_str(), false);
                    if (ImGui::IsItemClicked(ImGuiMouseButton_Left) && !aim_key.Capturing()) {
                        aim_key.Begin();
                        aiming.Reset();
                    }
                    ImGui::Dummy({0.0f, 8.0f});
                    CustomSlider("fov", &aim_settings.fov, 20.0f, 400.0f);
                    CustomSlider("smoothing", &aim_settings.smoothing, 1.0f, 20.0f);
                    CustomSlider("fov thickness", &fov_thickness, 1.0f, 3.0f);
                } else if (DebugControls()) {
                    game.Reload(sdk::ReloadTarget::all);
                    display.Clear();
                    cached_view.reset();
                    aiming.Reset();
                    status = game.Status();
                }

                ui_alpha = input.menu_alpha;
                ImGui::GetStyle().Alpha = ui_alpha;
                ImGui::EndChild();
            }
            ImGui::End();

            ImGui::GetStyle().Alpha = saved_alpha;
            ui_alpha = 1.0f;
        }
        const auto size = ImGui::GetIO().DisplaySize;
        bool aim_updated = false;
        if (aim_settings.enabled && aim_settings.show_fov)
            draw::Circle({size.x * 0.5f, size.y * 0.5f}, aim_settings.fov,
                ImGui::ColorConvertFloat4ToU32({fov_color[0], fov_color[1], fov_color[2], 1.0f}),
                fov_thickness);
        auto render_status = status;
        const auto render_now = std::chrono::steady_clock::now();
        if (!render_status.frame && display.frame &&
            render_now - display.frame->captured < DisplayCache::retention)
            render_status.frame = display.frame;
        if (game_active && render_status.pid == target.pid && render_status.frame &&
            render_now - render_status.frame->captured < std::chrono::milliseconds(175)) {
            if (display.Update(render_status.frame)) {
                cached_view.reset();
                aiming.Reset();
            }
            const auto valid_view = [](const auto& value) {
                return (value[3] != 0 || value[7] != 0 || value[11] != 0 || value[15] != 0) &&
                    std::all_of(value.begin(), value.end(), [](float v) { return std::isfinite(v); });
            };
            std::optional<sdk::skeleton::Matrix> view;
            const auto view_now = std::chrono::steady_clock::now();
            if (auto fresh = game.View(render_status); fresh && valid_view(*fresh)) {
                view = fresh;
                cached_view = view;
                cached_view_time = view_now;
            } else if (valid_view(render_status.frame->view) &&
                render_status.frame->captured >= cached_view_time) {
                view = render_status.frame->view;
                cached_view = view;
                cached_view_time = render_status.frame->captured;
            } else if (cached_view && view_now - cached_view_time < std::chrono::milliseconds(60))
                view = cached_view;
            if (view) {
                const sdk::skeleton::Projection camera(*view, size.x, size.y);
                const auto camera_position = sdk::skeleton::Eye(*view);
                if (status.frame) {
                    const auto movement = aiming.Update(*status.frame, *view, size.x, size.y, aim_settings,
                        aim_team_check, input.Owns(GetForegroundWindow()), aim_key.Held(), input.menu,
                        ImGui::GetIO().DeltaTime, view_now);
                    aim_updated = true;
                    if (movement && !input.menu && input.Owns(GetForegroundWindow()) && aim_key.Held())
                        mouse_event(MOUSEEVENTF_MOVE, static_cast<DWORD>(movement.x),
                            static_cast<DWORD>(movement.y), 0, 0);
                }
                std::erase_if(display.poses, [&](const auto& item) {
                    return view_now - item.second.captured >= DisplayCache::retention;
                });
                if (enabled || username_esp || operator_esp || health_esp || health_number_esp ||
                    weapon_esp || defuser_esp || box_esp)
                    for (auto& [identity, pose] : display.poses) {
                        const auto& entity = pose.value;
                        if (identity == render_status.frame->local_player)
                            continue;
                        const bool preview = render_status.frame->presentation && entity.unowned_model;

                        if (!preview && esp_team_check &&
                            (!entity.team_known || entity.teammate ||
                                view_now - pose.team_at >= std::chrono::milliseconds(150)))
                            continue;
                        draw::ScreenPose screen(entity.nodes, camera);
                        ImU32 skel_col = IM_COL32((int)(skeleton_color[0] * 255),
                            (int)(skeleton_color[1] * 255), (int)(skeleton_color[2] * 255), 255);
                        const auto head = head_circle
                            ? sdk::skeleton::HeadCircleGeometry(entity.nodes, *view, size.x, size.y)
                            : std::nullopt;
                        const auto bounds = box_esp || health_esp || health_number_esp || username_esp ||
                                operator_esp || weapon_esp || defuser_esp
                            ? draw::SkeletonBounds(screen, line_thickness, foot_bones, finger_bones,
                                  head_circle && head ? &*head : nullptr)
                            : std::nullopt;
                        if (box_esp && bounds) {
                            const ImU32 color = IM_COL32((int)(box_color[0] * 255), (int)(box_color[1] * 255),
                                (int)(box_color[2] * 255), 255);
                            draw::Box(*bounds, size, color, line_thickness);
                        }
                        if (enabled)
                            draw::Skeleton(screen, {0, 0}, size, skel_col, line_thickness, foot_bones,
                                finger_bones, head_circle && head ? &*head : nullptr);
                        if (enabled && head_circle && head) {
                            ImU32 hd_col = IM_COL32((int)(head_color[0] * 255), (int)(head_color[1] * 255),
                                (int)(head_color[2] * 255), 255);
                            draw::HeadCircle(*head, {0, 0}, size, hd_col, line_thickness);
                        }
                        const float label_distance = camera_position
                            ? std::hypot(entity.origin.x - camera_position->x,
                                  entity.origin.y - camera_position->y, entity.origin.z - camera_position->z)
                            : std::numeric_limits<float>::quiet_NaN();
                        const bool show_defuser = defuser_esp && entity.defuser.value_or(false);
                        if ((username_esp || operator_esp || show_defuser) && bounds) {
                            const ImU32 name_col = IM_COL32((int)(username_color[0] * 255),
                                (int)(username_color[1] * 255), (int)(username_color[2] * 255), 255);
                            auto* texture = operator_esp ? badges.Get(entity.operator_id) : nullptr;
                            draw::NameTag(entity.username, username_esp, operator_esp, show_defuser,
                                reinterpret_cast<ImTextureID>(texture), *bounds, size, name_col,
                                label_distance);
                        }
                        if ((health_esp || health_number_esp) && entity.health && bounds)
                            draw::Health(*entity.health, pose.health, *bounds, size, health_esp);
                        if (health_number_esp && entity.health && bounds)
                            draw::HealthNumber(*entity.health, pose.health, *bounds, size, label_distance);
                        if (weapon_esp && !entity.weapon.empty() && bounds) {
                            const ImU32 weapon_col = IM_COL32((int)(weapon_color[0] * 255),
                                (int)(weapon_color[1] * 255), (int)(weapon_color[2] * 255), 255);
                            draw::EquipmentLabel(entity.weapon, *bounds, size, weapon_col, label_distance);
                        }
                    }
            }
        } else {
            display.Clear();
            cached_view.reset();
        }
        if (!aim_updated)
            aiming.Reset();
        if (status.pid == target.pid && status.frame &&
            std::chrono::steady_clock::now() - status.frame->captured < std::chrono::milliseconds(175)) {
            char debug[96];
            snprintf(debug, sizeof(debug), "players init: %u/%u | skeletons: %zu", status.frame->initialized,
                status.frame->players, status.frame->GetPlayers().size());
            if (hud_ready) {
                hud_text = debug;
            }
        }
        if (hud_ready)
            DrawPlayerStatus(hud_text.c_str());
        else if (input.menu_alpha <= 0.01f)
            DrawLoading(status.progress, size);

        ImGui::Render();

        if (!input.ForegroundGame()) {
            input.Hide();
            continue;
        }

        const auto* output = ImGui::GetDrawData();
        scene_data.Clear();
        menu_data.Clear();
        scene_data.Valid = menu_data.Valid = true;
        scene_data.DisplayPos = output->DisplayPos;
        scene_data.DisplaySize = output->DisplaySize;
        scene_data.FramebufferScale = menu_data.FramebufferScale = output->FramebufferScale;
        scene_data.OwnerViewport = menu_data.OwnerViewport = output->OwnerViewport;
        menu_data.DisplayPos = {static_cast<float>(input.applied.left - origin.x),
            static_cast<float>(input.applied.top - origin.y)};
        menu_data.DisplaySize = {theme::panel_width, theme::panel_height};
        for (auto* list : output->CmdLists) {
            if (list == ImGui::GetBackgroundDrawList())
                scene_data.AddDrawList(list);
            else
                menu_data.AddDrawList(list);
        }
        constexpr float clear[]{0.0f, 0.0f, 0.0f, 0.0f};
        const auto render_surface = [&](ImDrawData& data, ID3D11RenderTargetView* target_view,
                                        IDXGISwapChain1* chain, bool& cleared) {
            const bool empty = data.TotalVtxCount == 0;
            if (empty && cleared)
                return S_OK;
            renderer.context->OMSetRenderTargets(1, &target_view, nullptr);
            renderer.context->ClearRenderTargetView(target_view, clear);
            if (data.TotalVtxCount != 0)
                ImGui_ImplDX11_RenderDrawData(&data);
            const auto presented = chain->Present(0, 0);
            if (SUCCEEDED(presented))
                cleared = empty;
            return presented;
        };
        HRESULT result =
            render_surface(scene_data, renderer.target.Get(), renderer.swap_chain.Get(), scene_cleared);
        const auto menu_result =
            render_surface(menu_data, renderer.menu_target.Get(), renderer.menu_chain.Get(), menu_cleared);
        if (FAILED(menu_result))
            result = menu_result;
        renderer.next_frame =
            FrameDeadline(frame_started, std::chrono::steady_clock::now(), renderer.interval);
        occluded = result == DXGI_STATUS_OCCLUDED;
        if (FAILED(result) && result != DXGI_ERROR_WAS_STILL_DRAWING) {
            exit_code = 1;
            break;
        }
    }

    input.Hide();
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    if (IsWindow(input.panel))
        DestroyWindow(input.panel);
    if (IsWindow(window))
        DestroyWindow(window);
    UnregisterClassW(cls.lpszClassName, instance);
    return exit_code;
}
}
