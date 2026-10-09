#pragma once

#include <optional>
#include <string>
#include <vector>

namespace vnm {

/// A local network interface with its primary IPv4 configuration.
struct Interface {
    std::string name;
    std::string ip;         // dotted quad
    std::string netmask;    // dotted quad
    std::string cidr;       // "192.168.1.10/24"
    std::string broadcast;
    std::string mac;
    bool up{false};
    bool loopback{false};
    bool has_ipv4{false};
};

/// One row of /proc/net/route.
struct Route {
    std::string destination; // dotted quad (0.0.0.0 for default)
    std::string gateway;     // dotted quad
    std::string interface_name;
    bool is_default{false};
};

/// Enumerates interfaces and routes without requiring elevated privileges.
class NetInfo {
public:
    /// Interfaces from getifaddrs() enriched with /sys/class/net metadata.
    [[nodiscard]] static std::vector<Interface> interfaces(
        const std::string& sysfs = "/sys/class/net");

    /// All IPv4 routes parsed from /proc/net/route.
    [[nodiscard]] static std::vector<Route> routes(
        const std::string& proc_route = "/proc/net/route");

    /// The default gateway route, if any.
    [[nodiscard]] static std::optional<Route> default_route(
        const std::string& proc_route = "/proc/net/route");

    /// Build "ip/prefix" from a dotted-quad address and netmask.
    [[nodiscard]] static std::string cidr_for(const std::string& ip,
                                              const std::string& netmask);

    /// Convert a dotted-quad netmask into a prefix length (0..32).
    [[nodiscard]] static int prefix_length(const std::string& netmask);
};

} // namespace vnm
