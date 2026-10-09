#include "vnm/net.hpp"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

namespace vnm {
namespace {

std::string read_first_line(const std::string& path) {
    std::ifstream in(path);
    std::string line;
    if (in && std::getline(in, line)) {
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
            line.pop_back();
        }
        return line;
    }
    return {};
}

std::string to_dotted(std::uint32_t value) {
    // /proc/net/route stores values little-endian.
    std::ostringstream os;
    os << (value & 0xFFu) << '.' << ((value >> 8) & 0xFFu) << '.'
       << ((value >> 16) & 0xFFu) << '.' << ((value >> 24) & 0xFFu);
    return os.str();
}

std::uint32_t parse_hex32(const std::string& text) {
    return static_cast<std::uint32_t>(std::strtoul(text.c_str(), nullptr, 16));
}

} // namespace

int NetInfo::prefix_length(const std::string& netmask) {
    in_addr addr{};
    if (::inet_pton(AF_INET, netmask.c_str(), &addr) != 1) {
        return 0;
    }
    const std::uint32_t mask = ntohl(addr.s_addr);
    int prefix = 0;
    for (int bit = 31; bit >= 0; --bit) {
        if ((mask >> bit) & 1u) {
            ++prefix;
        } else {
            break;
        }
    }
    return prefix;
}

std::string NetInfo::cidr_for(const std::string& ip, const std::string& netmask) {
    if (ip.empty()) {
        return {};
    }
    return ip + "/" + std::to_string(prefix_length(netmask));
}

std::vector<Interface> NetInfo::interfaces(const std::string& sysfs) {
    std::vector<Interface> result;

    ifaddrs* head = nullptr;
    if (::getifaddrs(&head) != 0) {
        return result;
    }

    for (ifaddrs* cur = head; cur != nullptr; cur = cur->ifa_next) {
        if (cur->ifa_addr == nullptr || cur->ifa_name == nullptr) {
            continue;
        }
        if (cur->ifa_addr->sa_family != AF_INET) {
            continue; // IPv4 only for the map's logical subnets
        }

        Interface iface;
        iface.name = cur->ifa_name;

        char buf[INET_ADDRSTRLEN] = {};
        auto* sin = reinterpret_cast<sockaddr_in*>(cur->ifa_addr);
        ::inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
        iface.ip = buf;
        iface.has_ipv4 = true;

        if (cur->ifa_netmask != nullptr) {
            auto* mask = reinterpret_cast<sockaddr_in*>(cur->ifa_netmask);
            char mbuf[INET_ADDRSTRLEN] = {};
            ::inet_ntop(AF_INET, &mask->sin_addr, mbuf, sizeof(mbuf));
            iface.netmask = mbuf;
        }
        if (cur->ifa_broadaddr != nullptr) {
            auto* bcast = reinterpret_cast<sockaddr_in*>(cur->ifa_broadaddr);
            char bbuf[INET_ADDRSTRLEN] = {};
            ::inet_ntop(AF_INET, &bcast->sin_addr, bbuf, sizeof(bbuf));
            iface.broadcast = bbuf;
        }

        iface.cidr = cidr_for(iface.ip, iface.netmask);
        iface.loopback = iface.ip.rfind("127.", 0) == 0;

        // Metadata from sysfs (best effort; path may not exist in containers).
        iface.mac = read_first_line(sysfs + "/" + iface.name + "/address");
        const std::string operstate =
            read_first_line(sysfs + "/" + iface.name + "/operstate");
        iface.up = (operstate == "up" || operstate == "unknown");

        result.push_back(std::move(iface));
    }

    ::freeifaddrs(head);
    return result;
}

std::vector<Route> NetInfo::routes(const std::string& proc_route) {
    std::vector<Route> result;
    std::ifstream in(proc_route);
    if (!in) {
        return result;
    }

    std::string line;
    std::getline(in, line); // header
    while (std::getline(in, line)) {
        std::istringstream is(line);
        std::string iface;
        std::string dest_hex;
        std::string gw_hex;
        std::string flags_hex;
        std::string refcnt;
        std::string use;
        std::string metric;
        std::string mask_hex;
        if (!(is >> iface >> dest_hex >> gw_hex >> flags_hex >> refcnt >> use >>
              metric >> mask_hex)) {
            continue;
        }

        Route route;
        route.interface_name = iface;
        route.destination = to_dotted(parse_hex32(dest_hex));
        route.gateway = to_dotted(parse_hex32(gw_hex));
        route.is_default = (parse_hex32(dest_hex) == 0u);
        result.push_back(std::move(route));
    }
    return result;
}

std::optional<Route> NetInfo::default_route(const std::string& proc_route) {
    for (const auto& route : routes(proc_route)) {
        if (route.is_default) {
            return route;
        }
    }
    return std::nullopt;
}

} // namespace vnm
