#include "vnm/live.hpp"

#include <cctype>
#include <cstdlib>
#include <sstream>

#include "vnm/layout.hpp"

namespace vnm {

void LiveOutputParser::reset() {
    scan_ = Scan{};
    current_ = -1;
}

int LiveOutputParser::find_or_add_host(const std::string& ip) {
    if (ip.empty()) {
        return -1;
    }
    for (std::size_t i = 0; i < scan_.hosts.size(); ++i) {
        if (scan_.hosts[i].address == ip) {
            return static_cast<int>(i);
        }
    }
    Host host;
    host.address = ip;
    host.status = HostStatus::Up;
    host.status_reason = "live";
    host.subnet = subnet_of(ip, 24);
    scan_.hosts.push_back(std::move(host));
    return static_cast<int>(scan_.hosts.size()) - 1;
}

void LiveOutputParser::add_open_port(Host& host, int number, const std::string& protocol) {
    for (auto& port : host.ports) {
        if (port.number == number && port.protocol == protocol) {
            port.state = "open";
            return;
        }
    }
    Port port;
    port.number = static_cast<std::uint16_t>(number);
    port.protocol = protocol;
    port.state = "open";
    host.ports.push_back(std::move(port));
}

void LiveOutputParser::feed_line(const std::string& line) {
    if (line.rfind("Nmap scan report for ", 0) == 0) {
        // Down hosts must be ignored -- nmap prints one "[host down]" line per
        // address that did not answer, which would otherwise flood the map.
        if (line.find("[host down]") != std::string::npos) {
            current_ = -1;
            return;
        }
        std::string rest = line.substr(21);
        const std::size_t mark = rest.find(" [host ");
        if (mark != std::string::npos) {
            rest = rest.substr(0, mark); // strip a trailing " [host up]" etc.
        }
        std::string ip = rest;
        const std::size_t lparen = rest.find('(');
        if (lparen != std::string::npos) {
            const std::size_t rparen = rest.find(')', lparen);
            if (rparen != std::string::npos) {
                ip = rest.substr(lparen + 1, rparen - lparen - 1);
            }
        } else {
            const std::size_t space = rest.find(' ');
            if (space != std::string::npos) {
                ip = rest.substr(0, space);
            }
        }
        current_ = find_or_add_host(ip);
        return;
    }

    // "Discovered open port N/proto on IP" carries its own IP, so it must be
    // handled before the "current host" guard (it often arrives before the
    // host report during the scan).
    if (line.rfind("Discovered open port ", 0) == 0) {
        const std::string rest = line.substr(21);
        const std::size_t slash = rest.find('/');
        const std::size_t on = rest.find(" on ");
        if (slash != std::string::npos && on != std::string::npos && on > slash) {
            const int number = std::atoi(rest.substr(0, slash).c_str());
            const std::string protocol = rest.substr(slash + 1, on - slash - 1);
            const int idx = find_or_add_host(rest.substr(on + 4));
            if (idx >= 0) {
                add_open_port(scan_.hosts[static_cast<std::size_t>(idx)], number, protocol);
            }
        }
        return;
    }

    if (current_ < 0 || static_cast<std::size_t>(current_) >= scan_.hosts.size()) {
        return;
    }
    Host& host = scan_.hosts[static_cast<std::size_t>(current_)];

    if (line.rfind("Host is up", 0) == 0) {
        host.status = HostStatus::Up;
        return;
    }
    if (line.rfind("MAC Address: ", 0) == 0) {
        const std::string rest = line.substr(13);
        const std::size_t space = rest.find(' ');
        host.mac = (space == std::string::npos) ? rest : rest.substr(0, space);
        const std::size_t lparen = rest.find('(');
        if (lparen != std::string::npos) {
            const std::size_t rparen = rest.find(')', lparen);
            if (rparen != std::string::npos) {
                host.vendor = rest.substr(lparen + 1, rparen - lparen - 1);
            }
        }
        return;
    }
    // Port table line, e.g. "22/tcp   open  ssh     OpenSSH 8.9p1".
    if (!line.empty() && std::isdigit(static_cast<unsigned char>(line[0]))) {
        const std::size_t slash = line.find('/');
        if (slash == std::string::npos) {
            return;
        }
        const int number = std::atoi(line.substr(0, slash).c_str());
        std::istringstream is(line.substr(slash + 1));
        std::string protocol;
        std::string state;
        std::string service;
        is >> protocol >> state >> service;
        add_open_port(host, number, protocol);
        for (auto& port : host.ports) {
            if (port.number == number && port.protocol == protocol) {
                if (!state.empty()) {
                    port.state = state;
                }
                if (!service.empty()) {
                    port.service = service;
                }
                break;
            }
        }
    }
}

} // namespace vnm
