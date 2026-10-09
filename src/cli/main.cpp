#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "vnm/diff.hpp"
#include "vnm/export.hpp"
#include "vnm/layout.hpp"
#include "vnm/net.hpp"
#include "vnm/parse.hpp"
#include "vnm/passive.hpp"
#include "vnm/scan.hpp"
#include "vnm/storage.hpp"

namespace {

constexpr const char* kVersion = "0.6.1";

void print_usage() {
    std::cout <<
        "vnm " << kVersion << " - Visual Network Mapper (CLI bootstrap)\n"
        "\n"
        "Usage:\n"
        "  vnm interfaces                 List local interfaces and default route\n"
        "  vnm scan <target> [options]    Run nmap, print and store hosts\n"
        "  vnm parse <file.xml> [--save]  Parse an Nmap XML result file\n"
        "  vnm layout <file.xml>          Show computed subnet clusters\n"
        "  vnm history                    List stored scans\n"
        "  vnm show <id>                  Print a stored scan\n"
        "  vnm diff <before_id> <after_id>  Compare two stored scans\n"
        "  vnm sniff [--iface <dev>] [--seconds N]  Passive ARP/DHCP discovery\n"
        "  vnm export <file.xml> [--format svg|png|json] [--out <path>]\n"
        "  vnm version                    Print version\n"
        "  vnm help                       Show this help\n"
        "\n"
        "Scan options:\n"
        "  --os                 Enable OS detection (-O, needs privileges)\n"
        "  --no-service         Disable service detection (-sV)\n"
        "  --no-save            Do not store the scan in the database\n"
        "  --nmap <path>        Use a specific nmap binary\n"
        "  -T<n>                Timing template (0..5)\n"
        "  --arg <value>        Pass an extra argument to nmap\n"
        "\n"
        "Storage:\n"
        "  Database path defaults to ~/.config/vnm/storage.db\n"
        "  Override with the VNM_DB environment variable.\n";
}

std::string storage_path() {
    if (const char* env = std::getenv("VNM_DB")) {
        if (*env != '\0') {
            return env;
        }
    }
    return vnm::Storage::default_path();
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

void print_diff(const vnm::ScanDiff& diff) {
    std::cout << "Diff: before=" << diff.total_before << " after=" << diff.total_after
              << "  +" << diff.added.size() << " -" << diff.removed.size()
              << " ~" << diff.changed.size() << " =unchanged " << diff.unchanged
              << "\n";
    if (diff.empty()) {
        std::cout << "No changes.\n";
        return;
    }
    for (const auto& host : diff.added) {
        std::cout << "  + " << host.address << "  [" << vnm::to_string(host.risk)
                  << "]  open=" << host.open_port_count() << '\n';
    }
    for (const auto& host : diff.removed) {
        std::cout << "  - " << host.address << "  (gone)\n";
    }
    for (const auto& change : diff.changed) {
        std::cout << "  ~ " << change.after.address;
        if (change.status_changed) {
            std::cout << "  status " << vnm::to_string(change.before.status) << " -> "
                      << vnm::to_string(change.after.status);
        }
        std::cout << '\n';
        for (const auto& port : change.added_ports) {
            std::cout << "      + " << port.describe() << '\n';
        }
        for (const auto& port : change.removed_ports) {
            std::cout << "      - " << port.describe() << '\n';
        }
        for (const auto& mod : change.modified_ports) {
            std::cout << "      ~ " << mod.before.describe() << "  =>  "
                      << mod.after.describe() << '\n';
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

bool save_scan_to_db(const vnm::Scan& scan) {
    vnm::Storage storage(storage_path());
    std::string error;
    if (!storage.open(&error)) {
        std::cerr << "warning: storage: " << error << '\n';
        return false;
    }
    const std::int64_t id = storage.save_scan(scan, &error);
    if (id == 0) {
        std::cerr << "warning: could not save scan: " << error << '\n';
        return false;
    }
    std::cout << "Stored as scan #" << id << " (" << storage.path() << ")\n";
    return true;
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

int cmd_parse(const std::string& path, bool save) {
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
    if (save) {
        save_scan_to_db(scan);
    }
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

int cmd_history() {
    vnm::Storage storage(storage_path());
    std::string error;
    if (!storage.open(&error)) {
        std::cerr << "error: " << error << '\n';
        return 1;
    }
    const std::vector<vnm::ScanSummary> scans = storage.list_scans(&error);
    if (!error.empty()) {
        std::cerr << "error: " << error << '\n';
        return 1;
    }
    if (scans.empty()) {
        std::cout << "No stored scans in " << storage.path() << '\n';
        return 0;
    }
    std::cout << "ID   Hosts  Created (UTC)         Nmap      Target\n";
    for (const auto& scan : scans) {
        std::cout << '#' << scan.id;
        std::cout << std::string(scan.id < 10 ? 3 : 2, ' ');
        std::cout << scan.host_count << "     " << scan.created_at << "  "
                  << (scan.nmap_version.empty() ? "-" : scan.nmap_version) << "  "
                  << scan.target << '\n';
    }
    return 0;
}

std::int64_t parse_id(const std::string& text) {
    return std::strtoll(text.c_str(), nullptr, 10);
}

int cmd_show(const std::string& id_text) {
    vnm::Storage storage(storage_path());
    std::string error;
    if (!storage.open(&error)) {
        std::cerr << "error: " << error << '\n';
        return 1;
    }
    const auto scan = storage.load_scan(parse_id(id_text), &error);
    if (!scan.has_value()) {
        std::cerr << "error: " << error << '\n';
        return 1;
    }
    print_scan(*scan);
    return 0;
}

int cmd_diff(const std::string& before_text, const std::string& after_text) {
    vnm::Storage storage(storage_path());
    std::string error;
    if (!storage.open(&error)) {
        std::cerr << "error: " << error << '\n';
        return 1;
    }
    const auto diff = storage.diff(parse_id(before_text), parse_id(after_text), &error);
    if (!diff.has_value()) {
        std::cerr << "error: " << error << '\n';
        return 1;
    }
    print_diff(*diff);
    return 0;
}

std::atomic<bool> g_sniff_stop{false};

void on_sigint(int) { g_sniff_stop.store(true); }

int cmd_sniff(int argc, char** argv, int start) {
    std::string iface;
    int seconds = 0;
    for (int i = start; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--iface" && i + 1 < argc) {
            iface = argv[++i];
        } else if (arg == "--seconds" && i + 1 < argc) {
            seconds = std::atoi(argv[++i]);
        } else {
            std::cerr << "error: unknown sniff option '" << arg << "'\n";
            return 1;
        }
    }

    if (!vnm::PassiveScanner::supported()) {
        std::cerr << "error: passive discovery not available "
                     "(built without libpcap/Npcap)\n";
        return 1;
    }

    if (iface.empty()) {
        const auto devices = vnm::PassiveScanner::devices();
        for (const auto& device : devices) {
            if (device.name == "lo") {
                continue; // Linux loopback
            }
            if (device.description.find("Loopback") != std::string::npos ||
                device.description.find("loopback") != std::string::npos) {
                continue;
            }
            iface = device.name;
            break;
        }
        if (iface.empty() && !devices.empty()) {
            iface = devices.front().name;
        }
        if (iface.empty()) {
            for (const auto& face : vnm::NetInfo::interfaces()) {
                if (!face.loopback) {
                    iface = face.name;
                    break;
                }
            }
        }
    }
    if (iface.empty()) {
        std::cerr << "error: no interface to sniff (use --iface)\n";
        return 1;
    }

    std::mutex mtx;
    std::map<std::string, vnm::PassiveObservation> table;
    vnm::PassiveScanner scanner;
    std::string error;
    const bool started = scanner.start(
        iface,
        [&](const vnm::PassiveObservation& obs) {
            std::lock_guard<std::mutex> lock(mtx);
            const std::string key = obs.mac.empty() ? obs.ip : obs.mac;
            auto& entry = table[key];
            if (entry.count == 0) {
                entry = obs;
            } else {
                entry.count += 1;
                entry.last_seen = obs.last_seen;
                if (obs.has_ip && !obs.ip.empty()) {
                    entry.ip = obs.ip;
                    entry.has_ip = true;
                }
                if (!obs.hostname.empty()) {
                    entry.hostname = obs.hostname;
                }
                if (!obs.vendor.empty()) {
                    entry.vendor = obs.vendor;
                }
            }
            std::cout << "  [" << obs.source << "] " << (obs.ip.empty() ? "-" : obs.ip)
                      << "  " << (obs.mac.empty() ? "-" : obs.mac);
            if (!obs.hostname.empty()) {
                std::cout << "  host=" << obs.hostname;
            }
            if (!obs.vendor.empty()) {
                std::cout << "  vendor=" << obs.vendor;
            }
            std::cout << std::endl;
        },
        &error);
    if (!started) {
        std::cerr << "error: " << error << '\n';
        return 1;
    }

    std::signal(SIGINT, on_sigint);
    std::cout << "Sniffing ARP/DHCP on '" << iface << "'";
    if (seconds > 0) {
        std::cout << " for " << seconds << "s";
    }
    std::cout << " (Ctrl-C to stop)\n";

    const auto begin = std::chrono::steady_clock::now();
    while (!g_sniff_stop.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        if (seconds > 0) {
            const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                                     std::chrono::steady_clock::now() - begin)
                                     .count();
            if (elapsed >= seconds) {
                break;
            }
        }
    }
    scanner.stop();

    std::cout << "\nObserved " << table.size() << " host(s), " << scanner.packets()
              << " packets\n";
    for (const auto& item : table) {
        const vnm::PassiveObservation& o = item.second;
        std::cout << "  " << (o.ip.empty() ? "-" : o.ip) << "  "
                  << (o.mac.empty() ? "-" : o.mac);
        if (!o.hostname.empty()) {
            std::cout << "  " << o.hostname;
        }
        if (!o.vendor.empty()) {
            std::cout << "  (" << o.vendor << ")";
        }
        std::cout << '\n';
    }
    return 0;
}

std::string basename_no_ext(const std::string& path) {
    const std::size_t slash = path.find_last_of("/\\");
    std::string name = slash == std::string::npos ? path : path.substr(slash + 1);
    const std::size_t dot = name.find_last_of('.');
    if (dot != std::string::npos && dot != 0) {
        name = name.substr(0, dot);
    }
    return name;
}

int cmd_export(int argc, char** argv, int start) {
    std::string input;
    std::string format = "svg";
    std::string out;
    std::string db = vnm::Storage::default_path();
    std::int64_t id = -1;

    for (int i = start; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--format" && i + 1 < argc) {
            format = argv[++i];
        } else if (arg == "--out" && i + 1 < argc) {
            out = argv[++i];
        } else if (arg == "--db" && i + 1 < argc) {
            db = argv[++i];
        } else if (arg == "--id" && i + 1 < argc) {
            id = parse_id(argv[++i]);
        } else if (input.empty()) {
            input = arg;
        } else {
            std::cerr << "error: unexpected argument '" << arg << "'\n";
            return 1;
        }
    }

    bool ok = false;
    const vnm::ExportFormat fmt = vnm::parse_format(format, &ok);
    if (!ok) {
        std::cerr << "error: unknown format '" << format
                  << "' (use svg|png|json)\n";
        return 1;
    }

    vnm::Scan scan;
    std::string base;
    if (id > 0) {
        vnm::Storage storage(db);
        std::string error;
        if (!storage.open(&error)) {
            std::cerr << "error: " << error << '\n';
            return 1;
        }
        const auto loaded = storage.load_scan(id, &error);
        if (!loaded.has_value()) {
            std::cerr << "error: " << error << '\n';
            return 1;
        }
        scan = *loaded;
        base = "vnm_scan_" + std::to_string(id);
    } else if (!input.empty()) {
        bool read = false;
        const std::string xml = slurp(input, read);
        if (!read) {
            std::cerr << "error: cannot read " << input << '\n';
            return 1;
        }
        scan = vnm::NmapXmlParser::parse(xml);
        if (scan.hosts.empty() && scan.nmap_version.empty()) {
            std::cerr << "error: no parseable Nmap XML in " << input << '\n';
            return 1;
        }
        base = basename_no_ext(input);
    } else {
        std::cerr << "error: provide <file.xml> or --id <n>\n";
        return 1;
    }

    if (out.empty()) {
        out = base + "." + vnm::to_string(fmt);
    }
    const vnm::TopologyLayout layout = vnm::layout_scan(scan);
    std::string error;
    if (!vnm::export_scan(scan, layout, fmt, out, &error)) {
        std::cerr << "error: " << error << '\n';
        return 1;
    }
    std::cout << "Exported " << scan.host_count() << " host(s) to " << out << '\n';
    return 0;
}

int cmd_scan(int argc, char** argv, int start) {
    if (start >= argc) {
        std::cerr << "error: missing scan target\n";
        return 1;
    }
    vnm::ScanOptions options;
    options.target = argv[start];
    bool save = true;

    for (int i = start + 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--os") {
            options.os_detection = true;
        } else if (arg == "--no-service") {
            options.service_detection = false;
        } else if (arg == "--no-save") {
            save = false;
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
    const vnm::Scan scan = vnm::NmapXmlParser::parse(xml);
    print_scan(scan);
    if (save) {
        save_scan_to_db(scan);
    }
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
        bool save = false;
        for (int i = 3; i < argc; ++i) {
            if (std::string(argv[i]) == "--save") {
                save = true;
            }
        }
        return cmd_parse(argv[2], save);
    } else if (cmd == "layout" && argc >= 3) {
        return cmd_layout(argv[2]);
    } else if (cmd == "history") {
        return cmd_history();
    } else if (cmd == "show" && argc >= 3) {
        return cmd_show(argv[2]);
    } else if (cmd == "diff" && argc >= 4) {
        return cmd_diff(argv[2], argv[3]);
    } else if (cmd == "sniff") {
        return cmd_sniff(argc, argv, 2);
    } else if (cmd == "export") {
        return cmd_export(argc, argv, 2);
    } else if (cmd == "scan") {
        return cmd_scan(argc, argv, 2);
    } else {
        std::cerr << "error: unknown command '" << cmd << "'\n";
        print_usage();
        return 1;
    }
    return 0;
}
