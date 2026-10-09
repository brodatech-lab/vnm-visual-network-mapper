#include "vnm/net.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601 // Windows 7+ (GetAdaptersAddresses / GetIpForwardTable2)
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include <map>
#else
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

namespace vnm {
namespace {

/// Parse a dotted-quad IPv4 into host byte order. Returns false on failure.
bool parse_ipv4(const std::string& text, std::uint32_t& out_host_order) {
#if defined(_WIN32)
    IN_ADDR addr{};
    if (InetPtonA(AF_INET, text.c_str(), &addr) != 1) {
        return false;
    }
    out_host_order = ntohl(addr.S_un.S_addr);
#else
    in_addr addr{};
    if (::inet_pton(AF_INET, text.c_str(), &addr) != 1) {
        return false;
    }
    out_host_order = ntohl(addr.s_addr);
#endif
    return true;
}

#if !defined(_WIN32)

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

#else // ------------------------------------------------ Windows helpers

std::string wide_to_utf8(const wchar_t* wide) {
    if (wide == nullptr) {
        return {};
    }
    const int size = WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        return {};
    }
    std::string out(static_cast<std::size_t>(size - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, out.data(), size, nullptr, nullptr);
    return out;
}

std::string dotted_from_host(std::uint32_t host_order) {
    std::ostringstream os;
    os << ((host_order >> 24) & 0xFFu) << '.' << ((host_order >> 16) & 0xFFu) << '.'
       << ((host_order >> 8) & 0xFFu) << '.' << (host_order & 0xFFu);
    return os.str();
}

std::string prefix_to_mask(int prefix) {
    if (prefix <= 0) {
        return "0.0.0.0";
    }
    if (prefix >= 32) {
        return "255.255.255.255";
    }
    const std::uint32_t mask = ~0u << (32 - prefix);
    return dotted_from_host(mask);
}

std::string sockaddr_to_string(const SOCKADDR_INET& addr) {
    if (addr.si_family == AF_INET) {
        char buf[INET_ADDRSTRLEN] = {};
        InetNtopA(AF_INET, &addr.Ipv4.sin_addr, buf, sizeof(buf));
        return buf;
    }
    if (addr.si_family == AF_INET6) {
        char buf[INET6_ADDRSTRLEN] = {};
        InetNtopA(AF_INET6, &addr.Ipv6.sin6_addr, buf, sizeof(buf));
        return buf;
    }
    return {};
}

std::map<DWORD, std::string> adapter_names() {
    std::map<DWORD, std::string> names;
    ULONG size = 0;
    const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                        GAA_FLAG_SKIP_DNS_SERVER;
    GetAdaptersAddresses(AF_INET, flags, nullptr, nullptr, &size);
    if (size == 0) {
        return names;
    }
    std::vector<BYTE> storage(size);
    auto* addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data());
    if (GetAdaptersAddresses(AF_INET, flags, nullptr, addrs, &size) != NO_ERROR) {
        return names;
    }
    for (auto* a = addrs; a != nullptr; a = a->Next) {
        names[a->IfIndex] = wide_to_utf8(a->FriendlyName);
    }
    return names;
}

#endif

} // namespace

int NetInfo::prefix_length(const std::string& netmask) {
    std::uint32_t mask = 0;
    if (!parse_ipv4(netmask, mask)) {
        return 0;
    }
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

#if !defined(_WIN32)

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

#else // ------------------------------------------------ Windows

std::vector<Interface> NetInfo::interfaces(const std::string&) {
    std::vector<Interface> result;

    const ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST |
                        GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG size = 0;
    GetAdaptersAddresses(AF_INET, flags, nullptr, nullptr, &size);
    if (size == 0) {
        return result;
    }
    std::vector<BYTE> storage(size);
    auto* addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data());
    if (GetAdaptersAddresses(AF_INET, flags, nullptr, addrs, &size) != NO_ERROR) {
        return result;
    }

    for (auto* a = addrs; a != nullptr; a = a->Next) {
        Interface iface;
        iface.name = wide_to_utf8(a->FriendlyName);

        for (auto* u = a->FirstUnicastAddress; u != nullptr; u = u->Next) {
            if (u->Address.lpSockaddr == nullptr ||
                u->Address.lpSockaddr->sa_family != AF_INET) {
                continue;
            }
            auto* sin = reinterpret_cast<sockaddr_in*>(u->Address.lpSockaddr);
            char buf[INET_ADDRSTRLEN] = {};
            InetNtopA(AF_INET, &sin->sin_addr, buf, sizeof(buf));
            iface.ip = buf;
            iface.has_ipv4 = true;

            const int prefix = static_cast<int>(u->OnLinkPrefixLength);
            iface.netmask = prefix_to_mask(prefix);
            iface.cidr = iface.ip + "/" + std::to_string(prefix);
            break;
        }
        if (!iface.has_ipv4) {
            continue;
        }

        iface.up = (a->OperStatus == IfOperStatusUp);
        iface.loopback = (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK);
        if (a->PhysicalAddressLength == 6) {
            char mac[18];
            std::snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                          a->PhysicalAddress[0], a->PhysicalAddress[1],
                          a->PhysicalAddress[2], a->PhysicalAddress[3],
                          a->PhysicalAddress[4], a->PhysicalAddress[5]);
            iface.mac = mac;
        }
        result.push_back(std::move(iface));
    }
    return result;
}

std::vector<Route> NetInfo::routes(const std::string&) {
    std::vector<Route> result;

    PMIB_IPFORWARD_TABLE2 table = nullptr;
    if (GetIpForwardTable2(AF_INET, &table) != NO_ERROR || table == nullptr) {
        return result;
    }
    const std::map<DWORD, std::string> names = adapter_names();

    for (ULONG i = 0; i < table->NumEntries; ++i) {
        const MIB_IPFORWARD_ROW2& row = table->Table[i];
        Route route;
        const auto it = names.find(row.InterfaceIndex);
        if (it != names.end()) {
            route.interface_name = it->second;
        }
        route.destination = sockaddr_to_string(row.DestinationPrefix.Prefix);
        route.gateway = sockaddr_to_string(row.NextHop);
        route.is_default = (row.DestinationPrefix.PrefixLength == 0);
        result.push_back(std::move(route));
    }

    FreeMibTable(table);
    return result;
}

#endif

std::optional<Route> NetInfo::default_route(const std::string& source) {
    for (const auto& route : routes(source)) {
        if (route.is_default) {
            return route;
        }
    }
    return std::nullopt;
}

} // namespace vnm
