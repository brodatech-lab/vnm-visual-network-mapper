#include "vnm/model.hpp"

#include <array>
#include <string_view>

namespace vnm {
namespace {

/// Service names considered inherently risky when exposed.
constexpr std::array<std::string_view, 9> kRiskyServices{
    "telnet", "ftp", "rlogin", "vnc", "smb", "microsoft-ds",
    "ms-wbt-server", "rdp", "netbios-ssn"};

bool is_risky_service(const std::string& service) {
    for (const auto svc : kRiskyServices) {
        if (service == svc) {
            return true;
        }
    }
    return false;
}

} // namespace

std::string Port::describe() const {
    std::string out = std::to_string(number) + "/" + protocol + " " + state;
    if (!service.empty()) {
        out += " " + service;
    }
    if (!product.empty()) {
        out += " (" + product;
        if (!version.empty()) {
            out += " " + version;
        }
        out += ")";
    }
    return out;
}

bool Host::has_open_port() const {
    for (const auto& port : ports) {
        if (port.state == "open") {
            return true;
        }
    }
    return false;
}

std::size_t Host::open_port_count() const {
    std::size_t count = 0;
    for (const auto& port : ports) {
        if (port.state == "open") {
            ++count;
        }
    }
    return count;
}

const char* to_string(HostStatus status) noexcept {
    switch (status) {
        case HostStatus::Up:      return "up";
        case HostStatus::Down:    return "down";
        case HostStatus::Unknown: break;
    }
    return "unknown";
}

const char* to_string(RiskLevel level) noexcept {
    switch (level) {
        case RiskLevel::Safe:     return "safe";
        case RiskLevel::Warning:  return "warning";
        case RiskLevel::Critical: return "critical";
        case RiskLevel::Offline:  return "offline";
        case RiskLevel::Unknown:  break;
    }
    return "unknown";
}

std::uint32_t risk_color(RiskLevel level) noexcept {
    // 0xRRGGBB
    switch (level) {
        case RiskLevel::Safe:     return 0x2ECC71; // green
        case RiskLevel::Warning:  return 0xF1C40F; // yellow
        case RiskLevel::Critical: return 0xE74C3C; // red
        case RiskLevel::Offline:  return 0x7F8C8D; // grey
        case RiskLevel::Unknown:  break;
    }
    return 0x95A5A6;
}

RiskLevel evaluate_risk(const Host& host) {
    if (host.status == HostStatus::Down) {
        return RiskLevel::Offline;
    }
    if (host.status == HostStatus::Unknown) {
        return RiskLevel::Unknown;
    }
    if (!host.has_open_port()) {
        return RiskLevel::Safe;
    }
    for (const auto& port : host.ports) {
        if (port.state == "open" && is_risky_service(port.service)) {
            return RiskLevel::Critical;
        }
    }
    return RiskLevel::Warning;
}

} // namespace vnm
