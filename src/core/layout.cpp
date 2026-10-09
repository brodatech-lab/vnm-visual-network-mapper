#include "vnm/layout.hpp"

#include <algorithm>
#include <cstdlib>
#include <map>
#include <string>

namespace vnm {

std::string subnet_of(const std::string& ip, int prefix) {
    if (ip.find(':') != std::string::npos) {
        return ip; // IPv6: keep as-is
    }
    unsigned octets[4] = {0, 0, 0, 0};
    int idx = 0;
    std::size_t start = 0;
    for (std::size_t i = 0; i <= ip.size() && idx < 4; ++i) {
        if (i == ip.size() || ip[i] == '.') {
            octets[idx++] = static_cast<unsigned>(
                std::strtoul(ip.substr(start, i - start).c_str(), nullptr, 10));
            start = i + 1;
        }
    }
    if (idx != 4) {
        return {};
    }
    const unsigned host = (octets[0] << 24) | (octets[1] << 16) |
                          (octets[2] << 8) | octets[3];
    const unsigned mask =
        prefix <= 0 ? 0u : (~0u << (32 - static_cast<unsigned>(prefix)));
    const unsigned net = host & mask;
    return std::to_string((net >> 24) & 0xFFu) + "." +
           std::to_string((net >> 16) & 0xFFu) + "." +
           std::to_string((net >> 8) & 0xFFu) + "." +
           std::to_string(net & 0xFFu) + "/" + std::to_string(prefix);
}

TopologyLayout layout_scan(const Scan& scan, const LayoutConfig& config) {
    TopologyLayout layout;

    std::map<std::string, std::vector<std::size_t>> groups;
    std::vector<std::string> order;
    for (std::size_t i = 0; i < scan.hosts.size(); ++i) {
        std::string key = scan.hosts[i].subnet;
        if (key.empty()) {
            key = subnet_of(scan.hosts[i].address, 24);
        }
        if (key.empty()) {
            key = "unknown";
        }
        if (groups.find(key) == groups.end()) {
            order.push_back(key);
        }
        groups[key].push_back(i);
    }

    std::sort(order.begin(), order.end());

    const int columns = std::max(1, config.columns_per_cluster);
    float cursor_y = 0.0f;
    float max_width = 0.0f;

    for (const auto& key : order) {
        SubnetCluster cluster;
        cluster.cidr = key;
        cluster.hosts = groups[key];

        const int count = static_cast<int>(cluster.hosts.size());
        const int rows = (count + columns - 1) / columns;
        const int cols_in_row = std::min(columns, count);

        cluster.width = config.cluster_padding * 2.0f +
                        static_cast<float>(cols_in_row) * config.node_width +
                        static_cast<float>(std::max(0, cols_in_row - 1)) *
                            config.node_gap_x;
        cluster.height = config.cluster_padding * 2.0f +
                         static_cast<float>(rows) * config.node_height +
                         static_cast<float>(std::max(0, rows - 1)) *
                             config.node_gap_y;
        cluster.x = 0.0f;
        cluster.y = cursor_y;

        for (int i = 0; i < count; ++i) {
            const int row = i / columns;
            const int col = i % columns;
            NodePosition pos;
            pos.host_index = cluster.hosts[static_cast<std::size_t>(i)];
            pos.x = cluster.x + config.cluster_padding +
                    static_cast<float>(col) *
                        (config.node_width + config.node_gap_x);
            pos.y = cluster.y + config.cluster_padding +
                    static_cast<float>(row) *
                        (config.node_height + config.node_gap_y);
            layout.nodes.push_back(pos);
        }

        cursor_y += cluster.height + config.cluster_gap;
        max_width = std::max(max_width, cluster.width);
        layout.clusters.push_back(std::move(cluster));
    }

    layout.width = max_width;
    layout.height = cursor_y > 0.0f ? cursor_y - config.cluster_gap : 0.0f;
    return layout;
}

} // namespace vnm
