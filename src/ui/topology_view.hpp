#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "imgui.h"
#include "vnm/layout.hpp"
#include "vnm/model.hpp"

namespace vnm::ui {

/// Mutable camera/interaction state for the topology canvas.
struct TopologyViewState {
    float zoom{1.0f};
    ImVec2 pan{0.0f, 0.0f};
    bool fit_requested{true};
    int selected{-1};      // host mirrored in the Inspector
    std::string search;    // filter query ("", "192.168", "port:22")

    // Manual node placement: world-space offset added to the layout position.
    std::unordered_map<std::size_t, ImVec2> node_offset;
    int dragging_node{-1};
    bool node_drag_moved{false};

    // Detail cards opened by clicking hosts (world-space, persistent).
    struct Chip {
        ImVec2 a{0.0f, 0.0f}; // screen rect of the clickable chip
        ImVec2 b{0.0f, 0.0f};
        std::string url;
    };
    struct Card {
        int host_index{-1};
        ImVec2 pos{0.0f, 0.0f};       // unclamped top-left (world space)
        ImVec2 rect_a{0.0f, 0.0f};    // last drawn rect (screen)
        ImVec2 rect_b{0.0f, 0.0f};
        ImVec2 close_a{0.0f, 0.0f};
        ImVec2 close_b{0.0f, 0.0f};
        bool dragging{false};
        std::vector<Chip> chips;      // rebuilt every frame while drawing
    };
    std::vector<Card> cards;
};

/// Draws the 2D topology into the current window and returns the host index
/// mirrored in the Inspector (or -1). Handles pan, zoom, node/card dragging,
/// selection and the minimap.
int draw_topology(const Scan& scan, const TopologyLayout& layout,
                  const LayoutConfig& config, TopologyViewState& state);

/// True when a host matches a filter query. Supports "port:<n>" and free text.
[[nodiscard]] bool host_matches(const Host& host, const std::string& query);

} // namespace vnm::ui
