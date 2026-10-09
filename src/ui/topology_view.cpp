#include "topology_view.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <unordered_map>
#include <vector>

namespace vnm::ui {
namespace {

ImU32 risk_u32(RiskLevel level) {
    const std::uint32_t rgb = risk_color(level);
    return IM_COL32((rgb >> 16) & 0xFF, (rgb >> 8) & 0xFF, rgb & 0xFF, 255);
}

ImU32 dim(ImU32 color, float factor) {
    const ImU32 a = static_cast<ImU32>(((color >> IM_COL32_A_SHIFT) & 0xFF) * factor);
    const ImU32 r = static_cast<ImU32>(((color >> IM_COL32_R_SHIFT) & 0xFF) * factor);
    const ImU32 g = static_cast<ImU32>(((color >> IM_COL32_G_SHIFT) & 0xFF) * factor);
    const ImU32 b = static_cast<ImU32>(((color >> IM_COL32_B_SHIFT) & 0xFF) * factor);
    return (a << IM_COL32_A_SHIFT) | (r << IM_COL32_R_SHIFT) |
           (g << IM_COL32_G_SHIFT) | (b << IM_COL32_B_SHIFT);
}

std::string lower(std::string text) {
    for (char& c : text) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return text;
}

bool contains_ci(const std::string& haystack, const std::string& needle) {
    return lower(haystack).find(needle) != std::string::npos;
}

float clampf(float v, float lo, float hi) {
    return std::min(std::max(v, lo), hi);
}

bool ends_with_dot_one(const std::string& address) {
    return address.size() >= 2 && address.compare(address.size() - 2, 2, ".1") == 0;
}

} // namespace

bool host_matches(const Host& host, const std::string& query) {
    if (query.empty()) {
        return true;
    }
    const std::string q = lower(query);
    if (q.rfind("port:", 0) == 0) {
        const std::string number = q.substr(5);
        for (const auto& port : host.ports) {
            if (std::to_string(port.number) == number) {
                return true;
            }
        }
        return false;
    }
    return contains_ci(host.address, q) || contains_ci(host.hostname, q) ||
           contains_ci(host.vendor, q) || contains_ci(host.os_name, q) ||
           contains_ci(host.mac, q);
}

int draw_topology(const Scan& scan, const TopologyLayout& layout,
                  const LayoutConfig& config, TopologyViewState& state) {
    ImVec2 canvas_p0 = ImGui::GetCursorScreenPos();
    ImVec2 canvas_sz = ImGui::GetContentRegionAvail();
    canvas_sz.x = std::max(canvas_sz.x, 64.0f);
    canvas_sz.y = std::max(canvas_sz.y, 64.0f);

    ImDrawList* draw = ImGui::GetWindowDrawList();
    ImGuiIO& io = ImGui::GetIO();

    ImGui::InvisibleButton("##topology_canvas", canvas_sz,
                           ImGuiButtonFlags_MouseButtonLeft |
                               ImGuiButtonFlags_MouseButtonRight |
                               ImGuiButtonFlags_MouseButtonMiddle);
    const bool hovered = ImGui::IsItemHovered();
    const bool active = ImGui::IsItemActive();

    if (state.fit_requested && layout.width > 0.0f && layout.height > 0.0f) {
        const float sx = (canvas_sz.x - 48.0f) / layout.width;
        const float sy = (canvas_sz.y - 48.0f) / layout.height;
        state.zoom = clampf(std::min(sx, sy), 0.15f, 4.0f);
        state.pan.x = (canvas_sz.x - layout.width * state.zoom) * 0.5f;
        state.pan.y = (canvas_sz.y - layout.height * state.zoom) * 0.5f;
        state.fit_requested = false;
    }

    // zoom about the mouse cursor
    if (hovered && io.MouseWheel != 0.0f) {
        const ImVec2 mouse = io.MousePos;
        const float before_x = (mouse.x - canvas_p0.x - state.pan.x) / state.zoom;
        const float before_y = (mouse.y - canvas_p0.y - state.pan.y) / state.zoom;
        state.zoom = clampf(state.zoom * std::pow(1.1f, io.MouseWheel), 0.15f, 6.0f);
        state.pan.x = mouse.x - canvas_p0.x - before_x * state.zoom;
        state.pan.y = mouse.y - canvas_p0.y - before_y * state.zoom;
    }

    // pan (drag)
    if (active && (ImGui::IsMouseDragging(ImGuiMouseButton_Left) ||
                   ImGui::IsMouseDragging(ImGuiMouseButton_Right) ||
                   ImGui::IsMouseDragging(ImGuiMouseButton_Middle))) {
        state.pan.x += io.MouseDelta.x;
        state.pan.y += io.MouseDelta.y;
    }

    const auto w2s = [&](float x, float y) {
        return ImVec2(canvas_p0.x + state.pan.x + x * state.zoom,
                      canvas_p0.y + state.pan.y + y * state.zoom);
    };

    draw->PushClipRect(canvas_p0, ImVec2(canvas_p0.x + canvas_sz.x, canvas_p0.y + canvas_sz.y), true);

    // background
    draw->AddRectFilled(canvas_p0, ImVec2(canvas_p0.x + canvas_sz.x, canvas_p0.y + canvas_sz.y),
                        IM_COL32(24, 26, 31, 255));

    // subnet frames
    for (const auto& cluster : layout.clusters) {
        const ImVec2 a = w2s(cluster.x, cluster.y);
        const ImVec2 b = w2s(cluster.x + cluster.width, cluster.y + cluster.height);
        draw->AddRectFilled(a, b, IM_COL32(33, 37, 45, 200), 8.0f);
        draw->AddRect(a, b, IM_COL32(72, 82, 98, 255), 8.0f, 0, 2.0f);
        draw->AddText(ImVec2(a.x + 10.0f, a.y + 6.0f), IM_COL32(150, 160, 175, 255),
                      cluster.cidr.c_str());
    }

    std::unordered_map<std::size_t, const NodePosition*> position_of;
    position_of.reserve(layout.nodes.size());
    for (const auto& node : layout.nodes) {
        position_of[node.host_index] = &node;
    }

    // edges from the subnet gateway (.1) to the other nodes
    for (const auto& cluster : layout.clusters) {
        const NodePosition* hub = nullptr;
        for (const std::size_t hi : cluster.hosts) {
            if (hi < scan.hosts.size() && ends_with_dot_one(scan.hosts[hi].address)) {
                hub = position_of[hi];
                break;
            }
        }
        if (hub == nullptr) {
            continue;
        }
        const ImVec2 hub_center = w2s(hub->x + config.node_width * 0.5f,
                                      hub->y + config.node_height * 0.5f);
        for (const std::size_t hi : cluster.hosts) {
            const NodePosition* node = position_of[hi];
            if (node == nullptr || node == hub) {
                continue;
            }
            const ImVec2 center = w2s(node->x + config.node_width * 0.5f,
                                      node->y + config.node_height * 0.5f);
            draw->AddLine(hub_center, center, IM_COL32(90, 100, 118, 120), 1.5f);
        }
    }

    // hosts
    ImFont* font = ImGui::GetFont();
    const float font_size = clampf(ImGui::GetFontSize() * state.zoom, 9.0f, 20.0f);
    const float small_size = clampf(font_size * 0.85f, 8.0f, 16.0f);

    for (const auto& node : layout.nodes) {
        if (node.host_index >= scan.hosts.size()) {
            continue;
        }
        const Host& host = scan.hosts[node.host_index];
        const ImVec2 a = w2s(node.x, node.y);
        const ImVec2 b = w2s(node.x + config.node_width, node.y + config.node_height);
        if (b.x < canvas_p0.x || a.x > canvas_p0.x + canvas_sz.x || b.y < canvas_p0.y ||
            a.y > canvas_p0.y + canvas_sz.y) {
            continue;
        }

        const bool match = host_matches(host, state.search);
        ImU32 border = risk_u32(host.risk);
        ImU32 fill = IM_COL32(40, 44, 52, 255);
        ImU32 title = IM_COL32(236, 239, 243, 255);
        ImU32 subtitle = IM_COL32(160, 168, 180, 255);
        if (!match) {
            border = dim(border, 0.3f);
            fill = IM_COL32(32, 33, 37, 140);
            title = dim(title, 0.4f);
            subtitle = dim(subtitle, 0.4f);
        }

        draw->AddRectFilled(a, b, fill, 6.0f);
        const float thickness =
            (state.selected == static_cast<int>(node.host_index)) ? 3.0f : 1.8f;
        draw->AddRect(a, b, border, 6.0f, 0, thickness);
        if (state.selected == static_cast<int>(node.host_index)) {
            state.selected_screen = ImVec2(b.x + 16.0f, a.y);
        }

        draw->AddText(font, font_size, ImVec2(a.x + 10.0f * state.zoom + 2.0f, a.y + 6.0f * state.zoom + 2.0f),
                      title, host.address.c_str());

        char detail[96];
        if (!host.hostname.empty()) {
            std::snprintf(detail, sizeof(detail), "%s", host.hostname.c_str());
        } else if (!host.vendor.empty()) {
            std::snprintf(detail, sizeof(detail), "%s", host.vendor.c_str());
        } else {
            std::snprintf(detail, sizeof(detail), "open:%zu",
                          static_cast<std::size_t>(host.open_port_count()));
        }
        draw->AddText(font, small_size,
                      ImVec2(a.x + 10.0f * state.zoom + 2.0f,
                             a.y + 6.0f * state.zoom + 2.0f + font_size + 3.0f),
                      subtitle, detail);
    }

    // minimap
    const float mm_w = 190.0f;
    const float mm_h = 140.0f;
    const ImVec2 mm_a(canvas_p0.x + canvas_sz.x - mm_w - 12.0f,
                      canvas_p0.y + canvas_sz.y - mm_h - 12.0f);
    const ImVec2 mm_b(mm_a.x + mm_w, mm_a.y + mm_h);
    draw->AddRectFilled(mm_a, mm_b, IM_COL32(18, 20, 24, 225), 6.0f);
    draw->AddRect(mm_a, mm_b, IM_COL32(80, 90, 105, 255), 6.0f);

    if (layout.width > 0.0f && layout.height > 0.0f) {
        const float scale = std::min((mm_w - 8.0f) / layout.width, (mm_h - 8.0f) / layout.height);
        for (const auto& node : layout.nodes) {
            if (node.host_index >= scan.hosts.size()) {
                continue;
            }
            const ImVec2 p(mm_a.x + 4.0f + node.x * scale, mm_a.y + 4.0f + node.y * scale);
            const ImVec2 q(p.x + std::max(2.0f, config.node_width * scale),
                           p.y + std::max(2.0f, config.node_height * scale));
            draw->AddRectFilled(p, q, risk_u32(scan.hosts[node.host_index].risk), 1.0f);
        }
        const float vx = (-state.pan.x) / state.zoom;
        const float vy = (-state.pan.y) / state.zoom;
        const ImVec2 va(mm_a.x + 4.0f + vx * scale, mm_a.y + 4.0f + vy * scale);
        const ImVec2 vb(va.x + (canvas_sz.x / state.zoom) * scale,
                        va.y + (canvas_sz.y / state.zoom) * scale);
        draw->AddRect(va, vb, IM_COL32(255, 255, 255, 170), 0.0f, 0, 1.5f);
    }

    draw->PopClipRect();

    // selection on click (no drag)
    if (hovered && ImGui::IsMouseReleased(ImGuiMouseButton_Left) &&
        io.MouseDragMaxDistanceSqr[0] < 36.0f) {
        const float wx = (io.MousePos.x - canvas_p0.x - state.pan.x) / state.zoom;
        const float wy = (io.MousePos.y - canvas_p0.y - state.pan.y) / state.zoom;
        int picked = -1;
        for (const auto& node : layout.nodes) {
            if (wx >= node.x && wx <= node.x + config.node_width && wy >= node.y &&
                wy <= node.y + config.node_height) {
                picked = static_cast<int>(node.host_index);
                const ImVec2 a = w2s(node.x, node.y);
                const ImVec2 b =
                    w2s(node.x + config.node_width, node.y + config.node_height);
                state.selected_screen = ImVec2(b.x + 16.0f, a.y);
                break;
            }
        }
        state.selected = picked;
    }

    return state.selected;
}

} // namespace vnm::ui
