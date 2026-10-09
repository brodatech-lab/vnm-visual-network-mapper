#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace vnm {

/// Lifecycle state of a discovered host.
enum class HostStatus { Up, Down, Unknown };

/// Derived security assessment used for node colouring on the 2D map.
///   Safe     -> green
///   Warning  -> yellow
///   Critical -> red
///   Offline  -> grey
///   Unknown  -> neutral
enum class RiskLevel { Safe, Warning, Critical, Offline, Unknown };

/// An NSE script result attached to a port or host.
struct Script {
    std::string id;      // e.g. "vulners", "smb-vuln-ms17-010"
    std::string output;  // raw script output
};

/// A single open/closed/filtered port together with detected service info.
struct Port {
    std::uint16_t number{0};
    std::string protocol;   // "tcp" / "udp"
    std::string state;      // "open" / "closed" / "filtered"
    std::string service;    // "ssh", "http", ...
    std::string product;    // "OpenSSH"
    std::string version;    // "8.9p1"
    std::string extrainfo;  // free-form NSE/Banner text
    std::vector<Script> scripts;      // NSE scripts run against this port
    std::vector<std::string> cves;    // CVE ids found in the script output

    [[nodiscard]] bool has_vuln() const { return !cves.empty(); }

    /// Human readable "22/tcp open ssh (OpenSSH 8.9p1)".
    [[nodiscard]] std::string describe() const;
};

/// A discovered host (an Nmap <host> node).
struct Host {
    std::string address;            // IPv4 / IPv6
    std::string mac;
    std::string vendor;             // OUI lookup result
    std::string hostname;
    std::string os_name;
    int os_confidence{0};           // 0..100
    HostStatus status{HostStatus::Unknown};
    std::string status_reason;      // nmap <status reason="..."> (e.g. syn-ack)
    RiskLevel risk{RiskLevel::Unknown};
    std::vector<Port> ports;
    std::vector<Script> scripts;      // host-level (hostscript) NSE results
    std::vector<std::string> cves;    // CVE ids found at host level
    std::string subnet;             // "192.168.1.0/24"

    [[nodiscard]] bool has_open_port() const;
    [[nodiscard]] std::size_t open_port_count() const;

    /// True when the host gave a real response (open port or a network-level
    /// discovery reason). Hosts assumed up without any response (e.g. nmap
    /// `-Pn`, reason "user-set"/"unknown-response") are not responsive.
    [[nodiscard]] bool is_responsive() const;
};

/// Result of one Nmap invocation.
struct Scan {
    std::int64_t id{0};
    std::string target;             // original target argument
    std::string started_at;         // ISO-8601
    std::string finished_at;        // ISO-8601
    std::string nmap_version;
    std::vector<Host> hosts;

    [[nodiscard]] std::size_t host_count() const { return hosts.size(); }
};

// -- helpers -----------------------------------------------------------------

[[nodiscard]] const char* to_string(HostStatus status) noexcept;
[[nodiscard]] const char* to_string(RiskLevel level) noexcept;

/// Map a risk level to the ANSI-independent hex RGB used by the UI/map.
[[nodiscard]] std::uint32_t risk_color(RiskLevel level) noexcept;

/// Derive a risk level from a host's ports and status.
[[nodiscard]] RiskLevel evaluate_risk(const Host& host);

} // namespace vnm
