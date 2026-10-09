#include "topology_view.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstddef>
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

bool point_in(ImVec2 p, ImVec2 a, ImVec2 b) {
    return p.x >= a.x && p.x <= b.x && p.y >= a.y && p.y <= b.y;
}

std::string subtitle_of(const Host& host) {
    if (!host.hostname.empty()) {
        return host.hostname;
    }
    if (!host.vendor.empty()) {
        return host.vendor;
    }
    return "open:" + std::to_string(host.open_port_count());
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

    if (hovered && io.MouseWheel != 0.0f) {
        const ImVec2 mouse = io.MousePos;
        const float before_x = (mouse.x - canvas_p0.x - state.pan.x) / state.zoom;
        const float before_y = (mouse.y - canvas_p0.y - state.pan.y) / state.zoom;
        state.zoom = clampf(state.zoom * std::pow(1.1f, io.MouseWheel), 0.15f, 6.0f);
        state.pan.x = mouse.x - canvas_p0.x - before_x * state.zoom;
        state.pan.y = mouse.y - canvas_p0.y - before_y * state.zoom;
    }

    const auto w2s = [&](float x, float y) {
        return ImVec2(canvas_p0.x + state.pan.x + x * state.zoom,
                      canvas_p0.y + state.pan.y + y * state.zoom);
    };
    const auto node_world = [&](const NodePosition& node) {
        ImVec2 p(node.x, node.y);
        const auto it = state.node_offset.find(node.host_index);
        if (it != state.node_offset.end()) {
            p.x += it->second.x;
            p.y += it->second.y;
        }
        return p;
    };

    const bool any_card_drag =
        std::any_of(state.cards.begin(), state.cards.end(),
                    [](const TopologyViewState::Card& c) { return c.dragging; });

    // ---- mouse press: start dragging a card or a node ----
    if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
        const ImVec2 m = io.MousePos;
        bool handled = false;
        for (auto& card : state.cards) {
            if (point_in(m, card.rect_a, card.rect_b)) {
                if (!point_in(m, card.close_a, card.close_b)) {
                    card.dragging = true;
                }
                handled = true;
                break;
            }
        }
        if (!handled) {
            const float wx = (m.x - canvas_p0.x - state.pan.x) / state.zoom;
            const float wy = (m.y - canvas_p0.y - state.pan.y) / state.zoom;
            for (const auto& node : layout.nodes) {
                const ImVec2 p = node_world(node);
                if (wx >= p.x && wx <= p.x + config.node_width && wy >= p.y &&
                    wy <= p.y + config.node_height) {
                    state.dragging_node = static_cast<int>(node.host_index);
                    state.node_drag_moved = false;
                    break;
                }
            }
        }
    }

    // ---- drag updates ----
    if (state.dragging_node >= 0 && ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
        if (ImGui::IsMouseDragging(ImGuiMouseButton_Left)) {
            ImVec2& offset =
                state.node_offset[static_cast<std::size_t>(state.dragging_node)];
            offset.x += io.MouseDelta.x / state.zoom;
            offset.y += io.MouseDelta.y / state.zoom;
            state.node_drag_moved = true;
        }
    }
    for (auto& card : state.cards) {
        if (card.dragging && ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
            card.pos.x += io.MouseDelta.x;
            card.pos.y += io.MouseDelta.y;
        }
    }

    // ---- pan (only when not dragging a node/card) ----
    if (active && state.dragging_node < 0 && !any_card_drag &&
        (ImGui::IsMouseDragging(ImGuiMouseButton_Left) ||
         ImGui::IsMouseDragging(ImGuiMouseButton_Right) ||
         ImGui::IsMouseDragging(ImGuiMouseButton_Middle))) {
        state.pan.x += io.MouseDelta.x;
        state.pan.y += io.MouseDelta.y;
    }

    draw->PushClipRect(canvas_p0,
                       ImVec2(canvas_p0.x + canvas_sz.x, canvas_p0.y + canvas_sz.y), true);
    draw->AddRectFilled(canvas_p0,
                        ImVec2(canvas_p0.x + canvas_sz.x, canvas_p0.y + canvas_sz.y),
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

    // gateway edges
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
        const ImVec2 hub_p = node_world(*hub);
        const ImVec2 hub_center =
            w2s(hub_p.x + config.node_width * 0.5f, hub_p.y + config.node_height * 0.5f);
        for (const std::size_t hi : cluster.hosts) {
            const NodePosition* node = position_of[hi];
            if (node == nullptr || node == hub) {
                continue;
            }
            const ImVec2 p = node_world(*node);
            const ImVec2 center =
                w2s(p.x + config.node_width * 0.5f, p.y + config.node_height * 0.5f);
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
        const ImVec2 wp = node_world(node);
        const ImVec2 a = w2s(wp.x, wp.y);
        const ImVec2 b = w2s(wp.x + config.node_width, wp.y + config.node_height);
        if (b.x < canvas_p0.x || a.x > canvas_p0.x + canvas_sz.x || b.y < canvas_p0.y ||
            a.y > canvas_p0.y + canvas_sz.y) {
            continue;
        }

        const bool match = host_matches(host, state.search);
        ImU32 border = risk_u32(host.risk);
        ImU32 fill = IM_COL32(40, 44, 52, 255);
        ImU32 title = IM_COL32(236, 239, 243, 255);
        ImU32 sub = IM_COL32(160, 168, 180, 255);
        if (!match) {
            border = dim(border, 0.3f);
            fill = IM_COL32(32, 33, 37, 140);
            title = dim(title, 0.4f);
            sub = dim(sub, 0.4f);
        }

        draw->AddRectFilled(a, b, fill, 6.0f);
        const float thickness =
            (state.selected == static_cast<int>(node.host_index)) ? 3.0f : 1.8f;
        draw->AddRect(a, b, border, 6.0f, 0, thickness);

        draw->AddText(font, font_size,
                      ImVec2(a.x + 10.0f * state.zoom + 2.0f, a.y + 6.0f * state.zoom + 2.0f),
                      title, host.address.c_str());
        draw->AddText(font, small_size,
                      ImVec2(a.x + 10.0f * state.zoom + 2.0f,
                             a.y + 6.0f * state.zoom + 2.0f + font_size + 3.0f),
                      sub, subtitle_of(host).c_str());
    }

    // ---- detail cards (drawn on the canvas, screen-space) ----
    constexpr float kCardWidth = 320.0f;
    for (auto& card : state.cards) {
        if (card.host_index < 0 ||
            static_cast<std::size_t>(card.host_index) >= scan.hosts.size()) {
            continue;
        }
        // clamp position into the canvas
        card.pos.x = clampf(card.pos.x, canvas_p0.x + 4.0f,
                            canvas_p0.x + canvas_sz.x - kCardWidth - 4.0f);
        card.pos.y = clampf(card.pos.y, canvas_p0.y + 4.0f,
                            canvas_p0.y + canvas_sz.y - 28.0f);

        const Host& host = scan.hosts[static_cast<std::size_t>(card.host_index)];
        const float fs = ImGui::GetFontSize();
        const float line_h = fs + 3.0f;
        const float pad = 12.0f;
        const float title_h = fs + 6.0f;

        std::vector<std::string> info;
        info.push_back("hostname: " +
                       (host.hostname.empty() ? std::string("-") : host.hostname));
        info.push_back("vendor:   " + (host.vendor.empty() ? std::string("-") : host.vendor));
        info.push_back("mac:      " + (host.mac.empty() ? std::string("-") : host.mac));
        info.push_back("os:       " + (host.os_name.empty() ? std::string("-") : host.os_name));
        info.push_back("status:   " + std::string(vnm::to_string(host.status)) +
                       (host.status_reason.empty() ? "" : " (" + host.status_reason + ")"));
        info.push_back("risk:     " + std::string(vnm::to_string(host.risk)));

        const std::size_t max_ports = 10;
        const std::size_t shown = std::min(max_ports, host.ports.size());
        float card_h = pad + title_h + 6.0f + static_cast<float>(info.size()) * line_h + pad;
        if (!host.ports.empty()) {
            card_h += 6.0f + line_h + static_cast<float>(shown) * line_h;
            if (host.ports.size() > shown) {
                card_h += line_h;
            }
        }
        const ImVec2 card_a = card.pos;
        const ImVec2 card_b(card_a.x + kCardWidth, card_a.y + card_h);

        // connector from the node to the card
        for (const auto& n : layout.nodes) {
            if (static_cast<int>(n.host_index) == card.host_index) {
                const ImVec2 wp = node_world(n);
                const ImVec2 node_anchor(
                    w2s(wp.x + config.node_width, wp.y + config.node_height * 0.5f));
                draw->AddLine(node_anchor, ImVec2(card_a.x, (card_a.y + card_b.y) * 0.5f),
                              IM_COL32(120, 130, 145, 170), 1.5f);
                break;
            }
        }

        draw->AddRectFilled(ImVec2(card_a.x + 3.0f, card_a.y + 3.0f),
                            ImVec2(card_b.x + 3.0f, card_b.y + 3.0f),
                            IM_COL32(0, 0, 0, 90), 8.0f);
        draw->AddRectFilled(card_a, card_b, IM_COL32(34, 37, 45, 250), 8.0f);
        draw->AddRect(card_a, card_b, risk_u32(host.risk), 8.0f, 0, 2.0f);

        float y = card_a.y + pad;
        draw->AddText(font, fs + 3.0f, ImVec2(card_a.x + pad, y),
                      IM_COL32(236, 239, 243, 255), host.address.c_str());
        y += title_h;
        for (const auto& text : info) {
            draw->AddText(font, fs, ImVec2(card_a.x + pad, y),
                          IM_COL32(176, 184, 196, 255), text.c_str());
            y += line_h;
        }
        if (!host.ports.empty()) {
            y += 6.0f;
            draw->AddText(font, fs, ImVec2(card_a.x + pad, y),
                          IM_COL32(140, 150, 165, 255), "ports:");
            y += line_h;
            for (std::size_t i = 0; i < shown; ++i) {
                const Port& port = host.ports[i];
                const std::string text = port.describe();
                const ImU32 col = (port.state == "open") ? IM_COL32(210, 216, 224, 255)
                                                         : IM_COL32(130, 138, 150, 255);
                draw->AddText(font, fs, ImVec2(card_a.x + pad, y), col, text.c_str());
                y += line_h;
            }
            if (host.ports.size() > shown) {
                const std::string more =
                    "+" + std::to_string(host.ports.size() - shown) + " more";
                draw->AddText(font, fs, ImVec2(card_a.x + pad, y),
                              IM_COL32(130, 138, 150, 255), more.c_str());
            }
        }

        card.rect_a = card_a;
        card.rect_b = card_b;
        card.close_a = ImVec2(card_b.x - 22.0f, card_a.y + 5.0f);
        card.close_b = ImVec2(card_b.x - 8.0f, card_a.y + 19.0f);
        const bool close_hovered = point_in(io.MousePos, card.close_a, card.close_b);
        draw->AddText(font, fs, ImVec2(card.close_a.x + 3.0f, card.close_a.y),
                      close_hovered ? IM_COL32(236, 239, 243, 255)
                                    : IM_COL32(150, 158, 170, 255),
                      "x");
        if (close_hovered) {
            ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
        }
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
        const float scale =
            std::min((mm_w - 8.0f) / layout.width, (mm_h - 8.0f) / layout.height);
        for (const auto& node : layout.nodes) {
            if (node.host_index >= scan.hosts.size()) {
                continue;
            }
            const ImVec2 wp = node_world(node);
            const ImVec2 p(mm_a.x + 4.0f + wp.x * scale, mm_a.y + 4.0f + wp.y * scale);
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

    // ---- release: finish drags, open/close cards ----
    if (hovered && ImGui::IsMouseReleased(ImGuiMouseButton_Left)) {
        const ImVec2 m = io.MousePos;
        if (state.dragging_node >= 0) {
            if (!state.node_drag_moved) {
                const int host_index = state.dragging_node;
                state.selected = host_index;
                auto it = std::find_if(
                    state.cards.begin(), state.cards.end(),
                    [host_index](const TopologyViewState::Card& c) {
                        return c.host_index == host_index;
                    });
                if (it != state.cards.end()) {
                    TopologyViewState::Card card = *it; // focus: move to front
                    state.cards.erase(it);
                    state.cards.push_back(card);
                } else {
                    ImVec2 pos(canvas_p0.x + 40.0f, canvas_p0.y + 40.0f);
                    for (const auto& n : layout.nodes) {
                        if (static_cast<int>(n.host_index) == host_index) {
                            const ImVec2 wp = node_world(n);
                            const ImVec2 screen = w2s(wp.x, wp.y);
                            pos = ImVec2(screen.x + config.node_width * state.zoom + 20.0f,
                                         screen.y);
                            break;
                        }
                    }
                    TopologyViewState::Card card;
                    card.host_index = host_index;
                    card.pos = pos;
                    state.cards.push_back(card);
                }
            }
            state.dragging_node = -1;
            state.node_drag_moved = false;
        } else {
            for (auto& card : state.cards) {
                card.dragging = false;
            }
            for (std::size_t i = 0; i < state.cards.size(); ++i) {
                if (point_in(m, state.cards[i].close_a, state.cards[i].close_b)) {
                    state.cards.erase(state.cards.begin() + static_cast<std::ptrdiff_t>(i));
                    break;
                }
            }
        }
    }

    return state.selected;
}

} // namespace vnm::ui
