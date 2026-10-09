#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "vnm/layout.hpp"
#include "vnm/net.hpp"
#include "vnm/parse.hpp"
#include "vnm/scan.hpp"
#include "vnm/storage.hpp"

namespace {

constexpr const char* kVersion = "0.1.0";

void print_usage() {
    std::cout <<
        "vnm " << kVersion << " - Visual Network Mapper (CLI bootstrap)\n"
        "\n"
        "Usage:\n"
        "  vnm interfaces                 List local interfaces and default route\n"
        "  vnm parse <file.xml>           Parse an Nmap XML result file\n"
        "  vnm scan <target> [options]    Run nmap and print discovered hosts\n"
        "  vnm layout <file.xml>          Show computed subnet clusters\n"
        "  vnm version                    Print version\n"
        "  vnm help                       Show this help\n"
        "\n"
        "Scan options:\n"
        "  --os                 Enable OS detection (-O, needs privileges)\n"
        "  --no-service         Disable service detection (-sV)\n"
        "  --nmap <path>        Use a specific nmap binary\n"
        "  -T<n>                Timing template (0..5)\n"
        "  --arg <value>        Pass an extra argument to nmap\n";
}

std::string risk_label(vnm::RiskLevel level) {
    return std::string(vnm::to_string(level));
}

void print_scan(const vnm::Scan& scan) {
    std::cout << "Scan target: " << scan.target << '\n';
    if (!scan.nmap_version.empty()) {
        std::cout << "Nmap:        " << scan.nmap_version << '\n';
    }
    std::cout << "Hosts:       " << scan.host_count() << "\n\n";

    for (const auto& host : scan.hosts) {
        std::cout << "  " << host.address;
        if (!host.hostname.empty()) {
            std::cout << "  (" << host.hostname << ")";
        }
        std::cout << "  [" << vnm::to_string(host.status) << "/"
                  << risk_label(host.risk) << "]";
        if (!host.mac.empty()) {
            std::cout << "  " << host.mac;
            if (!host.vendor.empty()) {
                std::cout << " (" << host.vendor << ")";
            }
        }
        std::cout << "  open=" << host.open_port_count() << '\n';
        for (const auto& port : host.ports) {
            if (port.state == "open") {
                std::cout << "      - " << port.describe() << '\n';
            }
        }
    }
}

std::string slurp(const std::string& path, bool& ok) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        ok = false;
        return {};
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    ok = true;
    return ss.str();
}

int cmd_interfaces() {
    const auto ifaces = vnm::NetInfo::interfaces();
    std::cout << "Interfaces (" << ifaces.size() << "):\n";
    for (const auto& iface : ifaces) {
        std::cout << "  " << iface.name
                  << "  ip=" << iface.ip
                  << "  cidr=" << iface.cidr
                  << "  mac=" << iface.mac
                  << (iface.up ? "  [up]" : "  [down]")
                  << (iface.loopback ? "  [loopback]" : "") << '\n';
    }
    if (const auto route = vnm::NetInfo::default_route()) {
        std::cout << "Default route: " << route->gateway
                  << " via " << route->interface_name << '\n';
    } else {
        std::cout << "Default route: (none)\n";
    }
    return 0;
}

int cmd_parse(const std::string& path) {
    bool ok = false;
    const std::string xml = slurp(path, ok);
    if (!ok) {
        std::cerr << "error: cannot read " << path << '\n';
        return 1;
    }
    vnm::Scan scan = vnm::NmapXmlParser::parse(xml);
    if (scan.hosts.empty() && scan.nmap_version.empty()) {
        std::cerr << "error: no parseable Nmap XML in " << path << '\n';
        return 1;
    }
    print_scan(scan);
    return 0;
}

int cmd_layout(const std::string& path) {
    bool ok = false;
    const std::string xml = slurp(path, ok);
    if (!ok) {
        std::cerr << "error: cannot read " << path << '\n';
        return 1;
    }
    const vnm::Scan scan = vnm::NmapXmlParser::parse(xml);
    const vnm::TopologyLayout layout = vnm::layout_scan(scan);
    std::cout << "Canvas: " << layout.width << " x " << layout.height << '\n';
    for (const auto& cluster : layout.clusters) {
        std::cout << "  " << cluster.cidr << "  hosts=" << cluster.hosts.size()
                  << "  size=" << cluster.width << "x" << cluster.height << '\n';
    }
    return 0;
}

int cmd_scan(int argc, char** argv, int start) {
    if (start >= argc) {
        std::cerr << "error: missing scan target\n";
        return 1;
    }
    vnm::ScanOptions options;
    options.target = argv[start];

    for (int i = start + 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--os") {
            options.os_detection = true;
        } else if (arg == "--no-service") {
            options.service_detection = false;
        } else if (arg == "--nmap" && i + 1 < argc) {
            options.nmap_path = argv[++i];
        } else if (arg.rfind("-T", 0) == 0 && arg.size() == 3) {
            options.timing = arg[2] - '0';
        } else if (arg == "--arg" && i + 1 < argc) {
            options.extra_args.emplace_back(argv[++i]);
        } else {
            options.extra_args.push_back(arg);
        }
    }

    vnm::NmapRunner runner;
    std::string xml;
    const vnm::ProcessResult result = runner.run(
        options, [&xml](std::string_view line) {
            xml.append(line);
            xml.push_back('\n');
        });

    if (!result.error.empty()) {
        std::cerr << "error: " << result.error << '\n';
        return 1;
    }
    if (xml.empty()) {
        std::cerr << "error: nmap produced no output\n";
        return 1;
    }
    print_scan(vnm::NmapXmlParser::parse(xml));
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage();
        return 0;
    }
    const std::string cmd = argv[1];

    if (cmd == "help" || cmd == "--help" || cmd == "-h") {
        print_usage();
    } else if (cmd == "version" || cmd == "--version") {
        std::cout << "vnm " << kVersion << '\n';
    } else if (cmd == "interfaces") {
        return cmd_interfaces();
    } else if (cmd == "parse" && argc >= 3) {
        return cmd_parse(argv[2]);
    } else if (cmd == "layout" && argc >= 3) {
        return cmd_layout(argv[2]);
    } else if (cmd == "scan") {
        return cmd_scan(argc, argv, 2);
    } else {
        std::cerr << "error: unknown command '" << cmd << "'\n";
        print_usage();
        return 1;
    }
    return 0;
}
