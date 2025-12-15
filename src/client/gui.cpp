//
// Created by cv2 on 15.12.2025.
//

#include "gui.hpp"
#include <imgui.h>
#include <imgui_stdlib.h>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>

// ==========================================
// STYLING
// ==========================================

// Applies a clean, flat, light theme inspired by neumorphic design.
void apply_style() {
    ImGuiStyle& style = ImGui::GetStyle();

    // Set rounding for a modern look
    style.WindowRounding = 5.0f;
    style.FrameRounding = 4.0f;
    style.GrabRounding = 4.0f;
    style.ScrollbarRounding = 6.0f;
    style.PopupRounding = 4.0f;

    // Remove borders for a flat appearance
    style.WindowBorderSize = 0.0f;
    style.FrameBorderSize = 0.0f;
    style.PopupBorderSize = 0.0f;

    // Spacing
    style.ItemSpacing = ImVec2(10, 8);
    style.ItemInnerSpacing = ImVec2(6, 6);
    style.WindowPadding = ImVec2(12, 12);

    // Color Palette
    ImVec4* colors = style.Colors;
    colors[ImGuiCol_Text]                   = ImVec4(0.10f, 0.10f, 0.10f, 1.00f);
    colors[ImGuiCol_TextDisabled]           = ImVec4(0.60f, 0.60f, 0.60f, 1.00f);
    colors[ImGuiCol_WindowBg]               = ImVec4(0.94f, 0.94f, 0.94f, 1.00f);
    colors[ImGuiCol_ChildBg]                = ImVec4(0.98f, 0.98f, 0.98f, 1.00f);
    colors[ImGuiCol_PopupBg]                = ImVec4(1.00f, 1.00f, 1.00f, 0.98f);
    colors[ImGuiCol_Border]                 = ImVec4(0.00f, 0.00f, 0.00f, 0.10f);
    colors[ImGuiCol_BorderShadow]           = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    colors[ImGuiCol_FrameBg]                = ImVec4(0.88f, 0.88f, 0.88f, 1.00f);
    colors[ImGuiCol_FrameBgHovered]         = ImVec4(0.92f, 0.92f, 0.92f, 0.78f);
    colors[ImGuiCol_FrameBgActive]          = ImVec4(1.00f, 1.00f, 1.00f, 1.00f);
    colors[ImGuiCol_TitleBg]                = ImVec4(0.96f, 0.96f, 0.96f, 1.00f);
    colors[ImGuiCol_TitleBgActive]          = ImVec4(0.82f, 0.82f, 0.82f, 1.00f);
    colors[ImGuiCol_TitleBgCollapsed]       = ImVec4(1.00f, 1.00f, 1.00f, 0.51f);
    colors[ImGuiCol_MenuBarBg]              = ImVec4(0.86f, 0.86f, 0.86f, 1.00f);
    colors[ImGuiCol_ScrollbarBg]            = ImVec4(0.98f, 0.98f, 0.98f, 0.53f);
    colors[ImGuiCol_ScrollbarGrab]          = ImVec4(0.69f, 0.69f, 0.69f, 0.80f);
    colors[ImGuiCol_ScrollbarGrabHovered]   = ImVec4(0.49f, 0.49f, 0.49f, 0.80f);
    colors[ImGuiCol_ScrollbarGrabActive]    = ImVec4(0.49f, 0.49f, 0.49f, 1.00f);
    colors[ImGuiCol_CheckMark]              = ImVec4(0.26f, 0.59f, 0.98f, 1.00f);
    colors[ImGuiCol_SliderGrab]             = ImVec4(0.26f, 0.59f, 0.98f, 0.78f);
    colors[ImGuiCol_SliderGrabActive]       = ImVec4(0.46f, 0.54f, 0.80f, 0.60f);
    colors[ImGuiCol_Button]                 = ImVec4(0.86f, 0.86f, 0.86f, 1.00f);
    colors[ImGuiCol_ButtonHovered]          = ImVec4(0.78f, 0.87f, 0.98f, 1.00f);
    colors[ImGuiCol_ButtonActive]           = ImVec4(0.59f, 0.73f, 0.98f, 1.00f);
    colors[ImGuiCol_Header]                 = ImVec4(0.90f, 0.90f, 0.90f, 0.45f);
    colors[ImGuiCol_HeaderHovered]          = ImVec4(0.90f, 0.90f, 0.90f, 0.80f);
    colors[ImGuiCol_HeaderActive]           = ImVec4(0.87f, 0.87f, 0.87f, 0.80f);
    colors[ImGuiCol_Separator]              = ImVec4(0.39f, 0.39f, 0.39f, 0.62f);
    colors[ImGuiCol_SeparatorHovered]       = ImVec4(0.14f, 0.44f, 0.80f, 0.78f);
    colors[ImGuiCol_SeparatorActive]        = ImVec4(0.14f, 0.44f, 0.80f, 1.00f);
    colors[ImGuiCol_ResizeGrip]             = ImVec4(0.80f, 0.80f, 0.80f, 0.56f);
    colors[ImGuiCol_ResizeGripHovered]      = ImVec4(0.26f, 0.59f, 0.98f, 0.67f);
    colors[ImGuiCol_ResizeGripActive]       = ImVec4(0.26f, 0.59f, 0.98f, 0.95f);
    colors[ImGuiCol_Tab]                    = ImVec4(0.76f, 0.80f, 0.84f, 0.93f);
    colors[ImGuiCol_TabHovered]             = ImVec4(0.26f, 0.59f, 0.98f, 0.80f);
    colors[ImGuiCol_TabActive]              = ImVec4(0.60f, 0.73f, 0.88f, 1.00f);
}

// ==========================================
// HELPERS
// ==========================================

// Converts bytes to KB, MB, GB for display
std::string format_bytes(uint64_t bytes) {
    if (bytes < 1024) return std::to_string(bytes) + " B";
    double kb = bytes / 1024.0;
    if (kb < 1024.0) {
        std::stringstream ss;
        ss << std::fixed << std::setprecision(2) << kb << " KB";
        return ss.str();
    }
    double mb = kb / 1024.0;
    if (mb < 1024.0) {
        std::stringstream ss;
        ss << std::fixed << std::setprecision(2) << mb << " MB";
        return ss.str();
    }
    double gb = mb / 1024.0;
    std::stringstream ss;
    ss << std::fixed << std::setprecision(2) << gb << " GB";
    return ss.str();
}

ImVec4 get_color_for_level(LogLevel level) {
    switch (level) {
        case LogLevel::SUCCESS: return {0.1f, 0.7f, 0.1f, 1.0f};
        case LogLevel::WARN:    return {0.9f, 0.6f, 0.0f, 1.0f};
        case LogLevel::ERROR:   return {0.8f, 0.1f, 0.1f, 1.0f};
        case LogLevel::DEBUG:   return {0.4f, 0.0f, 0.4f, 1.0f};
        case LogLevel::CMD:     return {0.6f, 0.0f, 1.0f, 1.0f};
        default:                return {0.5f, 0.5f, 0.5f, 1.0f};
    }
}

// ==========================================
// MAIN UI RENDER FUNCTION
// ==========================================
void render_ui(AppState& state) {
    // Make main window cover the entire OS window
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
    ImGui::Begin("StingVPN", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoBringToFrontOnFocus);

    // Get current connection status (thread-safe)
    auto status = state.connection_status.load();
    bool is_disconnected = (status == AppState::Status::DISCONNECTED || status == AppState::Status::FAILED);

    // ----------------------------------------
    // LEFT PANE: Controls & Status
    // ----------------------------------------
    ImGui::BeginChild("ControlsPane", ImVec2(300, 0), true);
    {
        ImGui::PushStyleVar(ImGuiStyleVar_Alpha, is_disconnected ? 1.0f : 0.5f);
        ImGui::BeginDisabled(!is_disconnected);

        ImGui::Text("Server Address");
        ImGui::InputText("##Server", &state.server_host);

        ImGui::Text("Username");
        ImGui::InputText("##Username", &state.username);

        ImGui::Text("Password");
        ImGui::InputText("##Password", &state.password, ImGuiInputTextFlags_Password);

        ImGui::EndDisabled();
        ImGui::PopStyleVar();

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // --- Connect/Disconnect Button ---
        if (is_disconnected) {
            if (ImGui::Button("Connect", ImVec2(-1, 30))) {
                if (state.lws_ctx) lws_cancel_service(state.lws_ctx);

                state.connect_request = true;
            }
        }  else {
            ImVec4 disconnect_color = ImVec4(0.8f, 0.2f, 0.2f, 1.0f);
            ImGui::PushStyleColor(ImGuiCol_Button, disconnect_color);
            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.9f, 0.3f, 0.3f, 1.0f));
            ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1.0f, 0.4f, 0.4f, 1.0f));
            if (ImGui::Button("Disconnect", ImVec2(-1, 30))) {
                if (state.lws_ctx) lws_cancel_service(state.lws_ctx);
                state.disconnect_request = true;
            }
            ImGui::PopStyleColor(3);
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // --- Status Display ---
        ImGui::Text("Status");
        ImGui::SameLine();
        const char* status_text;
        ImVec4 status_color;
        switch (status) {
            case AppState::Status::CONNECTED:    status_text = "Connected"; status_color = {0.1f, 0.8f, 0.1f, 1.0f}; break;
            case AppState::Status::CONNECTING:   status_text = "Connecting..."; status_color = {0.9f, 0.6f, 0.0f, 1.0f}; break;
            case AppState::Status::FAILED:       status_text = "Failed"; status_color = {0.8f, 0.1f, 0.1f, 1.0f}; break;
            case AppState::Status::DISCONNECTED:
            default:                             status_text = "Disconnected"; status_color = {0.5f, 0.5f, 0.5f, 1.0f}; break;
        }
        ImGui::TextColored(status_color, status_text);

        if (status == AppState::Status::CONNECTED) {
            ImGui::Text("Assigned IP:");
            ImGui::SameLine();
            ImGui::Text("%s", state.assigned_ip.c_str());
        }

        ImGui::Spacing();

        ImGui::Text("Traffic");
        ImGui::Text("  Sent:"); ImGui::SameLine(); ImGui::Text("%s", format_bytes(state.bytes_sent.load()).c_str());
        ImGui::Text("  Recv:"); ImGui::SameLine(); ImGui::Text("%s", format_bytes(state.bytes_received.load()).c_str());

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Text("Routing Exclusions");

        // --- Excluded IPs List ---
        static char new_ip_buf[64] = "";
        if (ImGui::InputText("##NewIP", new_ip_buf, sizeof(new_ip_buf), ImGuiInputTextFlags_EnterReturnsTrue)) {
             if (strlen(new_ip_buf) > 0) {
                state.excluded_ips.push_back(new_ip_buf);
                new_ip_buf[0] = '\0';
             }
        }
        ImGui::SameLine();
        if (ImGui::Button("Add")) {
            if (strlen(new_ip_buf) > 0) {
                state.excluded_ips.push_back(new_ip_buf);
                new_ip_buf[0] = '\0';
            }
        }

        ImGui::BeginChild("ExclusionsList");
        int ip_to_delete = -1;
        for (int i = 0; i < state.excluded_ips.size(); ++i) {
            ImGui::PushID(i);
            if (ImGui::Button("X")) {
                ip_to_delete = i;
            }
            ImGui::SameLine();
            ImGui::Text("%s", state.excluded_ips[i].c_str());
            ImGui::PopID();
        }
        if (ip_to_delete != -1) {
            state.excluded_ips.erase(state.excluded_ips.begin() + ip_to_delete);
        }
        ImGui::EndChild();
    }
    ImGui::EndChild();

    ImGui::SameLine();

    // ----------------------------------------
    // RIGHT PANE: Console Log
    // ----------------------------------------
    ImGui::BeginChild("ConsolePane", ImVec2(0, 0), true);
    {
        ImGui::Text("Console");
        ImGui::Separator();

        ImGui::BeginChild("LogArea", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()), false, ImGuiWindowFlags_HorizontalScrollbar);

        // Use a static vector to store logs so they persist
        static std::vector<std::pair<LogLevel, std::string>> logs;

        // Drain the queue from the network thread
        std::pair<LogLevel, std::string> log_entry;
        bool just_added_log = false;
        while (state.log_queue.try_pop(log_entry)) {
            logs.push_back(std::move(log_entry));
            just_added_log = true;
        }

        // Display logs
        for (const auto& entry : logs) {
            ImGui::TextColored(get_color_for_level(entry.first), "[%s]", entry.second.c_str());
        }

        // Auto-scroll to the bottom if a new message was added
        if (just_added_log && ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) {
            ImGui::SetScrollHereY(1.0f);
        }

        ImGui::EndChild();

        // --- Clear Log Button ---
        if (ImGui::Button("Clear Log")) {
            logs.clear();
        }
    }
    ImGui::EndChild();

    ImGui::End();
}