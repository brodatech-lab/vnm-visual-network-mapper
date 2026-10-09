#pragma once

#include <string>

#include "imgui.h"
#include "vnm/layout.hpp"
#include "vnm/model.hpp"

namespace vnm::ui {

/// Mutable camera/interaction state for the topology canvas.
struct TopologyViewState {
    float zoom{1.0f};
    ImVec2 pan{0.0f, 0.0f};
    bool fit_requested{true};
    int selected{-1};      // index into scan.hosts, -1 = none
    // Screen-space geometry of the selected node and of the drawn detail card
    // (used for the connector, external click handling and the close button).
    ImVec2 selected_node_a{0.0f, 0.0f};
    ImVec2 selected_node_b{0.0f, 0.0f};
    ImVec2 detail_rect_a{0.0f, 0.0f};
    ImVec2 detail_rect_b{0.0f, 0.0f};
    ImVec2 detail_close_a{0.0f, 0.0f};
    ImVec2 detail_close_b{0.0f, 0.0f};
    std::string search;    // filter query ("", "192.168", "port:22")
};

/// Draws the 2D topology into the current window and returns the selected host
/// index (or -1). Handles pan, zoom, selection and the minimap.
int draw_topology(const Scan& scan, const TopologyLayout& layout,
                  const LayoutConfig& config, TopologyViewState& state);

/// True when a host matches a filter query. Supports "port:<n>" and free text.
[[nodiscard]] bool host_matches(const Host& host, const std::string& query);

} // namespace vnm::ui
