#include "vnm/layout.hpp"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <map>
#include <string>

namespace vnm {
namespace {

constexpr float kPi = 3.14159265358979323846f;

bool ends_with_dot_one(const std::string& address) {
    return address.size() >= 2 && address.compare(address.size() - 2, 2, ".1") == 0;
}

} // namespace

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

    // Group hosts by subnet.
    std::map<std::string, std::vector<std::size_t>> groups;
    std::vector<std::string> order;
    for (std::size_t i = 0; i < scan.hosts.size(); ++i) {
        if (config.only_responsive && !scan.hosts[i].is_responsive()) {
            continue; // do not clutter the map with non-answering addresses
        }
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

    const float node_w = config.node_width;
    const float node_h = config.node_height;
    const float pad = config.cluster_padding;
    const float label_allow = config.node_height * 0.5f + 8.0f;

    float cursor_y = 0.0f;
    float max_width = 0.0f;

    for (const auto& key : order) {
        const std::vector<std::size_t>& hosts = groups[key];
        if (hosts.empty()) {
            continue;
        }

        // Pick the hub: the ".1" gateway when present, else the first host.
        std::size_t hub = hosts.front();
        for (const std::size_t hi : hosts) {
            if (ends_with_dot_one(scan.hosts[hi].address)) {
                hub = hi;
                break;
            }
        }

        std::vector<std::size_t> spokes;
        for (const std::size_t hi : hosts) {
            if (hi != hub) {
                spokes.push_back(hi);
            }
        }
        const std::size_t spoke_count = spokes.size();

        // Ring radius: enough circumference so spokes do not overlap the hub.
        float radius = 0.0f;
        if (spoke_count > 0) {
            const float by_circumference =
                static_cast<float>(spoke_count) * (node_w + config.node_gap_x) /
                (2.0f * kPi);
            radius = std::max(node_w * 1.0f, by_circumference);
        }

        const float box_w = 2.0f * radius + node_w + 2.0f * pad;
        const float box_h = 2.0f * radius + node_h + 2.0f * pad + label_allow;
        const float center_x = pad + radius + node_w * 0.5f;
        const float center_y = label_allow + pad + radius + node_h * 0.5f;

        SubnetCluster cluster;
        cluster.cidr = key;
        cluster.hosts = hosts;
        cluster.x = 0.0f;
        cluster.y = cursor_y;
        cluster.width = box_w;
        cluster.height = box_h;

        // Hub in the middle.
        NodePosition hub_pos;
        hub_pos.host_index = hub;
        hub_pos.x = center_x - node_w * 0.5f;
        hub_pos.y = cursor_y + center_y - node_h * 0.5f;
        layout.nodes.push_back(hub_pos);

        // Spokes evenly on the ring, first at the top.
        for (std::size_t i = 0; i < spoke_count; ++i) {
            const float angle = -kPi / 2.0f + 2.0f * kPi * static_cast<float>(i) /
                                                  static_cast<float>(spoke_count);
            NodePosition p;
            p.host_index = spokes[i];
            p.x = center_x + radius * std::cos(angle) - node_w * 0.5f;
            p.y = cursor_y + center_y + radius * std::sin(angle) - node_h * 0.5f;
            layout.nodes.push_back(p);
        }

        cursor_y += box_h + config.cluster_gap;
        max_width = std::max(max_width, box_w);
        layout.clusters.push_back(std::move(cluster));
    }

    layout.width = max_width;
    layout.height = cursor_y > 0.0f ? cursor_y - config.cluster_gap : 0.0f;
    return layout;
}

} // namespace vnm
