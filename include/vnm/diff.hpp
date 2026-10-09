#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "vnm/model.hpp"

namespace vnm {

/// A port whose details changed between scans (same port/protocol).
struct PortModification {
    Port before;
    Port after;
};

/// A host that exists in both scans but whose state changed.
struct HostChange {
    Host before;
    Host after;
    std::vector<Port> added_ports;             // open in `after`, not in `before`
    std::vector<Port> removed_ports;           // present in `before`, gone in `after`
    std::vector<PortModification> modified_ports; // same port, different details
    bool status_changed{false};
};

/// Result of comparing two scans (time-travel diff).
struct ScanDiff {
    std::vector<Host> added;
    std::vector<Host> removed;
    std::vector<HostChange> changed;
    std::size_t unchanged{0};
    std::size_t total_before{0};
    std::size_t total_after{0};

    [[nodiscard]] bool empty() const {
        return added.empty() && removed.empty() && changed.empty();
    }
};

/// Compare two scans keyed by host address (ipv4/ipv6).
[[nodiscard]] ScanDiff diff_scans(const Scan& before, const Scan& after);

/// True when status and the set of ports are identical.
[[nodiscard]] bool same_host_state(const Host& a, const Host& b);

} // namespace vnm
