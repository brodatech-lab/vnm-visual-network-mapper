#include "topology_view.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstddef>
#include <cstdio>
#include <unordered_map>
#include <vector>

#include "vnm/links.hpp"

namespace vnm::ui {
namespace {

struct Rect {
    float x0;
    float y0;
    float x1;
    float y1;
};

void open_url(const std::string& url) {
    ImGuiPlatformIO& platform_io = ImGui::GetPlatformIO();
    if (platform_io.Platform_OpenInShellFn != nullptr) {
        platform_io.Platform_OpenInShellFn(ImGui::GetCurrentContext(), url.c_str());
    }
}

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

    const float node_w = config.node_width;
    const float node_h = config.node_height;

    // address -> host index (for card lookup)
    std::unordered_map<std::string, std::size_t> index_by_addr;
    index_by_addr.reserve(scan.hosts.size());
    for (std::size_t i = 0; i < scan.hosts.size(); ++i) {
        index_by_addr[scan.hosts[i].address] = i;
    }

    const auto addr_of = [&](const NodePosition& node) -> const std::string& {
        static const std::string empty;
        if (node.host_index < scan.hosts.size()) {
            return scan.hosts[node.host_index].address;
        }
        return empty;
    };

    // ---- lazily place hosts (frozen once assigned, de-collided) ----
    std::unordered_map<std::size_t, ImVec2> cluster_center;
    for (const auto& cluster : layout.clusters) {
        const ImVec2 c(cluster.x + cluster.width * 0.5f, cluster.y + cluster.height * 0.5f);
        for (const std::size_t hi : cluster.hosts) {
            cluster_center[hi] = c;
        }
    }
    const float gap = std::max(config.node_gap_x, 16.0f);
    std::vector<Rect> placed;
    placed.reserve(state.node_pos.size() + layout.nodes.size());
    for (const auto& kv : state.node_pos) {
        placed.push_back(Rect{kv.second.x, kv.second.y, kv.second.x + node_w,
                              kv.second.y + node_h});
    }
    auto collides = [&](float x, float y) {
        for (const Rect& r : placed) {
            if (x < r.x1 + gap && x + node_w > r.x0 - gap && y < r.y1 + gap &&
                y + node_h > r.y0 - gap) {
                return true;
            }
        }
        return false;
    };
    for (const auto& node : layout.nodes) {
        const std::string& addr = addr_of(node);
        if (addr.empty() || state.node_pos.count(addr) != 0) {
            continue;
        }
        float x = node.x;
        float y = node.y;
        if (collides(x, y)) {
            const auto it = cluster_center.find(node.host_index);
            const ImVec2 center = it != cluster_center.end() ? it->second
                                                             : ImVec2(x, y);
            const float cx = x + node_w * 0.5f - center.x;
            const float cy = y + node_h * 0.5f - center.y;
            const float base_r = std::sqrt(cx * cx + cy * cy);
            const float angle = std::atan2(cy, cx);
            for (int k = 1; k <= 80; ++k) {
                const float r = base_r + static_cast<float>(k) * (node_h + gap);
                const float nx = center.x + r * std::cos(angle) - node_w * 0.5f;
                const float ny = center.y + r * std::sin(angle) - node_h * 0.5f;
                if (!collides(nx, ny)) {
                    x = nx;
                    y = ny;
                    break;
                }
            }
        }
        state.node_pos[addr] = ImVec2(x, y);
        placed.push_back(Rect{x, y, x + node_w, y + node_h});
    }

    const auto node_world = [&](const NodePosition& node) -> ImVec2 {
        if (node.host_index < scan.hosts.size()) {
            const auto it = state.node_pos.find(scan.hosts[node.host_index].address);
            if (it != state.node_pos.end()) {
                return it->second;
            }
        }
        return ImVec2(node.x, node.y);
    };

    // ---- world bounds (frozen positions may exceed the layout extents) ----
    float minx = 0.0f;
    float miny = 0.0f;
    float maxx = 0.0f;
    float maxy = 0.0f;
    bool have_bounds = false;
    for (const auto& node : layout.nodes) {
        const ImVec2 p = node_world(node);
        if (!have_bounds) {
            have_bounds = true;
            minx = p.x;
            miny = p.y;
            maxx = p.x + node_w;
            maxy = p.y + node_h;
        } else {
            minx = std::min(minx, p.x);
            miny = std::min(miny, p.y);
            maxx = std::max(maxx, p.x + node_w);
            maxy = std::max(maxy, p.y + node_h);
        }
    }
    if (!have_bounds) {
        maxx = std::max(layout.width, 320.0f);
        maxy = std::max(layout.height, 200.0f);
    }
    const float world_w = std::max(maxx - minx, 1.0f);
    const float world_h = std::max(maxy - miny, 1.0f);

    if (state.fit_requested) {
        const float sx = (canvas_sz.x - 48.0f) / world_w;
        const float sy = (canvas_sz.y - 48.0f) / world_h;
        state.zoom = clampf(std::min(sx, sy), 0.15f, 4.0f);
        state.pan.x = (canvas_sz.x - world_w * state.zoom) * 0.5f - minx * state.zoom;
        state.pan.y = (canvas_sz.y - world_h * state.zoom) * 0.5f - miny * state.zoom;
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

    const bool any_card_drag =
        std::any_of(state.cards.begin(), state.cards.end(),
                    [](const TopologyViewState::Card& c) { return c.dragging; });

    // ---- mouse press: link chip, card, or node ----
    if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
        const ImVec2 m = io.MousePos;
        bool handled = false;
        for (int i = static_cast<int>(state.cards.size()) - 1; i >= 0 && !handled; --i) {
            for (const auto& chip : state.cards[static_cast<std::size_t>(i)].chips) {
                if (point_in(m, chip.a, chip.b)) {
                    open_url(chip.url);
                    handled = true;
                    break;
                }
            }
        }
        int clicked_card = -1;
        if (!handled) {
            for (int i = static_cast<int>(state.cards.size()) - 1; i >= 0; --i) {
                TopologyViewState::Card& card = state.cards[static_cast<std::size_t>(i)];
                if (point_in(m, card.rect_a, card.rect_b)) {
                    if (!point_in(m, card.close_a, card.close_b)) {
                        card.dragging = true;
                    }
                    clicked_card = i;
                    handled = true;
                    break;
                }
            }
            if (clicked_card >= 0 &&
                clicked_card != static_cast<int>(state.cards.size()) - 1) {
                TopologyViewState::Card card =
                    state.cards[static_cast<std::size_t>(clicked_card)];
                state.cards.erase(state.cards.begin() +
                                  static_cast<std::ptrdiff_t>(clicked_card));
                state.cards.push_back(card);
            }
        }
        if (!handled) {
            const float wx = (m.x - canvas_p0.x - state.pan.x) / state.zoom;
            const float wy = (m.y - canvas_p0.y - state.pan.y) / state.zoom;
            for (const auto& node : layout.nodes) {
                const ImVec2 p = node_world(node);
                if (wx >= p.x && wx <= p.x + node_w && wy >= p.y && wy <= p.y + node_h) {
                    state.dragging_node = static_cast<int>(node.host_index);
                    state.node_drag_moved = false;
                    break;
                }
            }
        }
    }

    // ---- drag updates ----
    if (state.dragging_node >= 0 && ImGui::IsMouseDown(ImGuiMouseButton_Left) &&
        static_cast<std::size_t>(state.dragging_node) < scan.hosts.size()) {
        if (ImGui::IsMouseDragging(ImGuiMouseButton_Left)) {
            ImVec2& pos = state.node_pos[scan.hosts[state.dragging_node].address];
            pos.x += io.MouseDelta.x / state.zoom;
            pos.y += io.MouseDelta.y / state.zoom;
            state.node_drag_moved = true;
        }
    }
    for (auto& card : state.cards) {
        if (card.dragging && ImGui::IsMouseDown(ImGuiMouseButton_Left)) {
            card.pos.x += io.MouseDelta.x / state.zoom;
            card.pos.y += io.MouseDelta.y / state.zoom;
        }
    }

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

    std::unordered_map<std::size_t, const NodePosition*> position_of;
    position_of.reserve(layout.nodes.size());
    for (const auto& node : layout.nodes) {
        position_of[node.host_index] = &node;
    }

    // subnet frames (recomputed from current node positions)
    const float frame_pad = config.cluster_padding;
    const float label_h = ImGui::GetFontSize() + 12.0f;
    for (const auto& cluster : layout.clusters) {
        bool any = false;
        float cx0 = 0.0f;
        float cy0 = 0.0f;
        float cx1 = 0.0f;
        float cy1 = 0.0f;
        for (const std::size_t hi : cluster.hosts) {
            const NodePosition* node = position_of[hi];
            if (node == nullptr) {
                continue;
            }
            const ImVec2 wp = node_world(*node);
            if (!any) {
                any = true;
                cx0 = wp.x;
                cy0 = wp.y;
                cx1 = wp.x + node_w;
                cy1 = wp.y + node_h;
            } else {
                cx0 = std::min(cx0, wp.x);
                cy0 = std::min(cy0, wp.y);
                cx1 = std::max(cx1, wp.x + node_w);
                cy1 = std::max(cy1, wp.y + node_h);
            }
        }
        if (!any) {
            continue;
        }
        const ImVec2 a = w2s(cx0 - frame_pad, cy0 - frame_pad - label_h);
        const ImVec2 b = w2s(cx1 + frame_pad, cy1 + frame_pad);
        draw->AddRectFilled(a, b, IM_COL32(33, 37, 45, 200), 8.0f);
        draw->AddRect(a, b, IM_COL32(72, 82, 98, 255), 8.0f, 0, 2.0f);
        draw->AddText(ImVec2(a.x + 10.0f, a.y + 6.0f), IM_COL32(150, 160, 175, 255),
                      cluster.cidr.c_str());
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
        const ImVec2 hp = node_world(*hub);
        const ImVec2 hub_center =
            w2s(hp.x + node_w * 0.5f, hp.y + node_h * 0.5f);
        for (const std::size_t hi : cluster.hosts) {
            const NodePosition* node = position_of[hi];
            if (node == nullptr || node == hub) {
                continue;
            }
            const ImVec2 p = node_world(*node);
            const ImVec2 center = w2s(p.x + node_w * 0.5f, p.y + node_h * 0.5f);
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
        const ImVec2 b = w2s(wp.x + node_w, wp.y + node_h);
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

    // ---- detail cards (world-space, so they scale with zoom) ----
    const float base = ImGui::GetFontSize();
    const float card_font = clampf(base * state.zoom, 9.0f, 20.0f);
    const float card_title = clampf((base + 3.0f) * state.zoom, 10.0f, 22.0f);
    const float line_h_w = base + 3.0f;
    const float pad_w = 12.0f;
    const float title_h_w = base + 6.0f;
    const float card_w_w = 400.0f;
    const float close_pad = 6.0f;
    const float chip_pad = 6.0f;
    const float chip_gap = 4.0f;
    const float chip_indent = 12.0f;

    for (auto& card : state.cards) {
        const auto host_it = index_by_addr.find(card.address);
        if (host_it == index_by_addr.end()) {
            continue;
        }
        const Host& host = scan.hosts[host_it->second];
        card.chips.clear();

        std::vector<std::string> info;
        info.push_back("hostname: " +
                       (host.hostname.empty() ? std::string("-") : host.hostname));
        info.push_back("vendor:   " + (host.vendor.empty() ? std::string("-") : host.vendor));
        info.push_back("mac:      " + (host.mac.empty() ? std::string("-") : host.mac));
        info.push_back("os:       " + (host.os_name.empty() ? std::string("-") : host.os_name));
        info.push_back("status:   " + std::string(vnm::to_string(host.status)) +
                       (host.status_reason.empty() ? "" : " (" + host.status_reason + ")"));
        info.push_back("risk:     " + std::string(vnm::to_string(host.risk)));

        const std::size_t max_ports = 12;
        const std::size_t shown = std::min(max_ports, host.ports.size());
        const float row_start = card.pos.x + pad_w + chip_indent;
        const float row_right = card.pos.x + card_w_w - pad_w;

        auto row_count = [&](const std::vector<vnm::RefLink>& links) -> int {
            if (links.empty()) {
                return 0;
            }
            float x = row_start;
            int rows = 1;
            for (const auto& link : links) {
                const float w = ImGui::CalcTextSize(link.label.c_str()).x + chip_pad * 2.0f;
                if (x + w > row_right && x > row_start) {
                    ++rows;
                    x = row_start;
                }
                x += w + chip_gap;
            }
            return rows;
        };
        const float chip_block = line_h_w + 3.0f;

        float card_h_w =
            pad_w + title_h_w + 6.0f + static_cast<float>(info.size()) * line_h_w + pad_w;
        if (!host.ports.empty()) {
            card_h_w += 6.0f + line_h_w;
            for (std::size_t i = 0; i < shown; ++i) {
                card_h_w += line_h_w;
                if (host.ports[i].state == "open") {
                    card_h_w +=
                        3.0f + static_cast<float>(
                                   row_count(vnm::port_links(host, host.ports[i]))) *
                                   chip_block;
                }
            }
            if (host.ports.size() > shown) {
                card_h_w += line_h_w;
            }
        }
        const std::vector<vnm::RefLink> host_links = vnm::host_links(host);
        if (!host_links.empty()) {
            card_h_w += 6.0f + line_h_w + 3.0f +
                        static_cast<float>(row_count(host_links)) * chip_block;
        }

        const ImVec2 card_a = w2s(card.pos.x, card.pos.y);
        const ImVec2 card_b = w2s(card.pos.x + card_w_w, card.pos.y + card_h_w);

        const auto node_it = std::find_if(
            layout.nodes.begin(), layout.nodes.end(),
            [&](const NodePosition& n) {
                return n.host_index < scan.hosts.size() &&
                       scan.hosts[n.host_index].address == card.address;
            });
        if (node_it != layout.nodes.end()) {
            const ImVec2 wp = node_world(*node_it);
            const ImVec2 node_anchor = w2s(wp.x + node_w, wp.y + node_h * 0.5f);
            draw->AddLine(node_anchor, ImVec2(card_a.x, (card_a.y + card_b.y) * 0.5f),
                          IM_COL32(120, 130, 145, 170),
                          std::max(1.0f, 1.5f * state.zoom));
        }

        draw->AddRectFilled(ImVec2(card_a.x + 3.0f, card_a.y + 3.0f),
                            ImVec2(card_b.x + 3.0f, card_b.y + 3.0f),
                            IM_COL32(0, 0, 0, 80), 8.0f);
        draw->AddRectFilled(card_a, card_b, IM_COL32(34, 37, 45, 250), 8.0f);
        draw->AddRect(card_a, card_b, risk_u32(host.risk), 8.0f, 0,
                      std::max(1.0f, 2.0f * state.zoom));

        float wy = card.pos.y + pad_w;
        draw->AddText(font, card_title, w2s(card.pos.x + pad_w, wy),
                      IM_COL32(236, 239, 243, 255), host.address.c_str());
        wy += title_h_w;
        for (const auto& text : info) {
            draw->AddText(font, card_font, w2s(card.pos.x + pad_w, wy),
                          IM_COL32(176, 184, 196, 255), text.c_str());
            wy += line_h_w;
        }

        auto draw_chips = [&](const std::vector<vnm::RefLink>& links) {
            if (links.empty()) {
                return;
            }
            float x = row_start;
            float y = wy + 3.0f;
            for (const auto& link : links) {
                const float w = ImGui::CalcTextSize(link.label.c_str()).x + chip_pad * 2.0f;
                if (x + w > row_right && x > row_start) {
                    x = row_start;
                    y += chip_block;
                }
                ImU32 fill = IM_COL32(38, 46, 58, 255);
                ImU32 border = IM_COL32(70, 110, 170, 255);
                ImU32 text_color = IM_COL32(120, 180, 255, 255);
                if (link.kind == vnm::LinkKind::Service) {
                    fill = IM_COL32(36, 46, 42, 255);
                    border = IM_COL32(60, 120, 80, 255);
                    text_color = IM_COL32(150, 210, 160, 255);
                } else if (link.kind == vnm::LinkKind::Exploit) {
                    fill = IM_COL32(54, 44, 30, 255);
                    border = IM_COL32(150, 100, 40, 255);
                    text_color = IM_COL32(245, 175, 80, 255);
                } else if (link.kind == vnm::LinkKind::Cve) {
                    fill = IM_COL32(60, 32, 34, 255);
                    border = IM_COL32(175, 70, 70, 255);
                    text_color = IM_COL32(250, 120, 110, 255);
                }
                const ImVec2 ca = w2s(x, y);
                const ImVec2 cb = w2s(x + w, y + line_h_w);
                const bool hovered_chip = point_in(io.MousePos, ca, cb);
                draw->AddRectFilled(ca, cb,
                                    hovered_chip ? IM_COL32(72, 82, 98, 255) : fill, 4.0f);
                draw->AddRect(ca, cb, border, 4.0f, 0, 1.0f);
                draw->AddText(font, card_font, w2s(x + chip_pad, y + 1.0f), text_color,
                              link.label.c_str());
                if (hovered_chip) {
                    ImGui::SetMouseCursor(ImGuiMouseCursor_Hand);
                }
                TopologyViewState::Chip chip;
                chip.a = ca;
                chip.b = cb;
                chip.url = link.url;
                card.chips.push_back(chip);
                x += w + chip_gap;
            }
            wy = y + chip_block;
        };

        if (!host.ports.empty()) {
            wy += 6.0f;
            draw->AddText(font, card_font, w2s(card.pos.x + pad_w, wy),
                          IM_COL32(140, 150, 165, 255), "ports:");
            wy += line_h_w;
            for (std::size_t i = 0; i < shown; ++i) {
                const Port& port = host.ports[i];
                const ImU32 col = (port.state == "open") ? IM_COL32(210, 216, 224, 255)
                                                         : IM_COL32(130, 138, 150, 255);
                draw->AddText(font, card_font, w2s(card.pos.x + pad_w, wy), col,
                              port.describe().c_str());
                wy += line_h_w;
                if (port.state == "open") {
                    draw_chips(vnm::port_links(host, port));
                }
            }
            if (host.ports.size() > shown) {
                const std::string more =
                    "+" + std::to_string(host.ports.size() - shown) + " more";
                draw->AddText(font, card_font, w2s(card.pos.x + pad_w, wy),
                              IM_COL32(130, 138, 150, 255), more.c_str());
                wy += line_h_w;
            }
        }
        if (!host_links.empty()) {
            wy += 6.0f;
            draw->AddText(font, card_font, w2s(card.pos.x + pad_w, wy),
                          IM_COL32(200, 120, 120, 255), "host vulns:");
            wy += line_h_w;
            draw_chips(host_links);
        }

        card.rect_a = card_a;
        card.rect_b = card_b;
        const float cs = clampf(16.0f * state.zoom, 10.0f, 28.0f);
        card.close_a =
            ImVec2(card_b.x - cs - close_pad * state.zoom, card_a.y + close_pad * state.zoom);
        card.close_b =
            ImVec2(card_b.x - close_pad * state.zoom, card_a.y + close_pad * state.zoom + cs);
        const bool close_hovered = point_in(io.MousePos, card.close_a, card.close_b);
        draw->AddText(font, card_font, ImVec2(card.close_a.x + 2.0f, card.close_a.y),
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
    {
        const float scale =
            std::min((mm_w - 8.0f) / world_w, (mm_h - 8.0f) / world_h);
        for (const auto& node : layout.nodes) {
            if (node.host_index >= scan.hosts.size()) {
                continue;
            }
            const ImVec2 wp = node_world(node);
            const ImVec2 p(mm_a.x + 4.0f + (wp.x - minx) * scale,
                           mm_a.y + 4.0f + (wp.y - miny) * scale);
            const ImVec2 q(p.x + std::max(2.0f, node_w * scale),
                           p.y + std::max(2.0f, node_h * scale));
            draw->AddRectFilled(p, q, risk_u32(scan.hosts[node.host_index].risk), 1.0f);
        }
        const float vx = (-state.pan.x) / state.zoom;
        const float vy = (-state.pan.y) / state.zoom;
        const ImVec2 va(mm_a.x + 4.0f + (vx - minx) * scale,
                        mm_a.y + 4.0f + (vy - miny) * scale);
        const ImVec2 vb(va.x + (canvas_sz.x / state.zoom) * scale,
                        va.y + (canvas_sz.y / state.zoom) * scale);
        draw->AddRect(va, vb, IM_COL32(255, 255, 255, 170), 0.0f, 0, 1.5f);
    }

    draw->PopClipRect();

    // ---- release: finish drags, open/close cards ----
    if (hovered && ImGui::IsMouseReleased(ImGuiMouseButton_Left)) {
        const ImVec2 m = io.MousePos;
        if (state.dragging_node >= 0) {
            if (!state.node_drag_moved &&
                static_cast<std::size_t>(state.dragging_node) < scan.hosts.size()) {
                const std::string& address = scan.hosts[state.dragging_node].address;
                state.selected = state.dragging_node;
                auto it = std::find_if(
                    state.cards.begin(), state.cards.end(),
                    [&](const TopologyViewState::Card& c) { return c.address == address; });
                if (it != state.cards.end()) {
                    TopologyViewState::Card card = *it;
                    state.cards.erase(it);
                    state.cards.push_back(card);
                } else {
                    ImVec2 pos(0.0f, 0.0f);
                    for (const auto& n : layout.nodes) {
                        if (static_cast<int>(n.host_index) == state.dragging_node) {
                            const ImVec2 wp = node_world(n);
                            pos = ImVec2(wp.x + node_w + 20.0f, wp.y);
                            break;
                        }
                    }
                    TopologyViewState::Card card;
                    card.address = address;
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
                    state.cards.erase(state.cards.begin() +
                                      static_cast<std::ptrdiff_t>(i));
                    break;
                }
            }
        }
    }

    return state.selected;
}

} // namespace vnm::ui
