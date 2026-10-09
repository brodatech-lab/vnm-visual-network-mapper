#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "vnm/model.hpp"

namespace vnm {

/// Screen-space placement of a single host node.
struct NodePosition {
    std::size_t host_index{0};
    float x{0.0f};
    float y{0.0f};
};

/// A rectangular frame grouping all hosts that share one /24 subnet.
struct SubnetCluster {
    std::string cidr;
    std::vector<std::size_t> hosts;
    float x{0.0f};
    float y{0.0f};
    float width{0.0f};
    float height{0.0f};
};

/// Deterministic topological layout ready to be drawn by the 2D canvas.
struct TopologyLayout {
    std::vector<NodePosition> nodes;
    std::vector<SubnetCluster> clusters;
    float width{0.0f};
    float height{0.0f};
};

struct LayoutConfig {
    float node_width{170.0f};
    float node_height{52.0f};
    float node_gap_x{24.0f};
    float node_gap_y{24.0f};
    float cluster_padding{28.0f};
    float cluster_gap{48.0f};
    int columns_per_cluster{4};
};

/// Groups hosts by subnet into frames and lays each cluster out on a grid.
[[nodiscard]] TopologyLayout layout_scan(const Scan& scan,
                                         const LayoutConfig& config = {});

/// Compute the /prefix network base address for an IPv4 string.
/// Returns an empty string for non-IPv4 input.
[[nodiscard]] std::string subnet_of(const std::string& ip, int prefix = 24);

} // namespace vnm
