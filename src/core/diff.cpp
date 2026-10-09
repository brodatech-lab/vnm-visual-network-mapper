#include "vnm/diff.hpp"

#include <map>
#include <string>

namespace vnm {
namespace {

using PortKey = std::pair<std::uint16_t, std::string>;

PortKey key_of(const Port& port) {
    return PortKey{port.number, port.protocol};
}

bool port_equal(const Port& a, const Port& b) {
    return a.number == b.number && a.protocol == b.protocol &&
           a.state == b.state && a.service == b.service &&
           a.product == b.product && a.version == b.version;
}

std::map<PortKey, const Port*> index_ports(const Host& host) {
    std::map<PortKey, const Port*> index;
    for (const auto& port : host.ports) {
        index.emplace(key_of(port), &port);
    }
    return index;
}

bool ports_equal(const Host& a, const Host& b) {
    const auto before = index_ports(a);
    const auto after = index_ports(b);
    if (before.size() != after.size()) {
        return false;
    }
    for (const auto& [key, port] : before) {
        const auto it = after.find(key);
        if (it == after.end() || !port_equal(*port, *it->second)) {
            return false;
        }
    }
    return true;
}

} // namespace

bool same_host_state(const Host& a, const Host& b) {
    return a.status == b.status && ports_equal(a, b);
}

ScanDiff diff_scans(const Scan& before, const Scan& after) {
    ScanDiff result;
    result.total_before = before.hosts.size();
    result.total_after = after.hosts.size();

    std::map<std::string, const Host*> before_by_addr;
    for (const auto& host : before.hosts) {
        before_by_addr.emplace(host.address, &host);
    }

    std::map<std::string, const Host*> after_by_addr;
    for (const auto& host : after.hosts) {
        after_by_addr.emplace(host.address, &host);
    }

    for (const auto& host : after.hosts) {
        const auto it = before_by_addr.find(host.address);
        if (it == before_by_addr.end()) {
            result.added.push_back(host);
            continue;
        }
        const Host& old = *it->second;
        if (same_host_state(old, host)) {
            ++result.unchanged;
            continue;
        }

        HostChange change;
        change.status_changed = (old.status != host.status);

        const auto old_ports = index_ports(old);
        const auto new_ports = index_ports(host);

        for (const auto& [key, port] : new_ports) {
            const auto old_it = old_ports.find(key);
            if (old_it == old_ports.end()) {
                change.added_ports.push_back(*port);
            } else if (!port_equal(*old_it->second, *port)) {
                change.modified_ports.push_back(PortModification{*old_it->second, *port});
            }
        }
        for (const auto& [key, port] : old_ports) {
            if (new_ports.find(key) == new_ports.end()) {
                change.removed_ports.push_back(*port);
            }
        }

        change.before = old;
        change.after = host;
        result.changed.push_back(std::move(change));
    }

    for (const auto& host : before.hosts) {
        if (after_by_addr.find(host.address) == after_by_addr.end()) {
            result.removed.push_back(host);
        }
    }

    return result;
}

} // namespace vnm
