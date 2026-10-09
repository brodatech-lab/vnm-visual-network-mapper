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
    ImVec2 selected_screen{0.0f, 0.0f}; // screen anchor of the selected node
    std::string search;    // filter query ("", "192.168", "port:22")
};

/// Draws the 2D topology into the current window and returns the selected host
/// index (or -1). Handles pan, zoom, selection and the minimap.
int draw_topology(const Scan& scan, const TopologyLayout& layout,
                  const LayoutConfig& config, TopologyViewState& state);

/// True when a host matches a filter query. Supports "port:<n>" and free text.
[[nodiscard]] bool host_matches(const Host& host, const std::string& query);

} // namespace vnm::ui
