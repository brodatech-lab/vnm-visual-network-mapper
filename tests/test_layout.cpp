#include "test_util.hpp"

#include "vnm/layout.hpp"

int main() {
    using namespace vnm;

    Scan scan;
    for (int i = 1; i <= 5; ++i) {
        Host h;
        h.address = "192.168.1." + std::to_string(i);
        h.status = HostStatus::Up;
        h.subnet = "192.168.1.0/24";
        scan.hosts.push_back(std::move(h));
    }
    for (int i = 1; i <= 2; ++i) {
        Host h;
        h.address = "10.0.0." + std::to_string(i);
        h.subnet = "10.0.0.0/24";
        scan.hosts.push_back(std::move(h));
    }

    const TopologyLayout layout = layout_scan(scan);
    CHECK(layout.nodes.size() == 7);
    CHECK(layout.clusters.size() == 2);
    CHECK(layout.clusters[0].cidr == "10.0.0.0/24"); // sorted
    CHECK(layout.clusters[1].cidr == "192.168.1.0/24");
    CHECK(layout.width > 0.0f);
    CHECK(layout.height > 0.0f);

    for (const auto& node : layout.nodes) {
        CHECK(node.x >= 0.0f);
        CHECK(node.y >= 0.0f);
    }

    CHECK(subnet_of("192.168.1.77", 24) == "192.168.1.0/24");
    CHECK(subnet_of("10.5.9.1", 16) == "10.5.0.0/16");
    CHECK(subnet_of("not-an-ip") == "");
    CHECK(subnet_of("fe80::1", 64) == "fe80::1");

    return vnmtest::summary("layout");
}
