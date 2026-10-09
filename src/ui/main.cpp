#include <GLFW/glfw3.h>

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "imgui_internal.h"

#include <atomic>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#ifndef VNM_VERSION
#define VNM_VERSION "dev"
#endif

#include "icon.hpp"
#include "topology_view.hpp"
#include "vnm/export.hpp"
#include "vnm/layout.hpp"
#include "vnm/links.hpp"
#include "vnm/model.hpp"
#include "vnm/net.hpp"
#include "vnm/parse.hpp"
#include "vnm/passive.hpp"
#include "vnm/platform.hpp"
#include "vnm/scan.hpp"
#include "vnm/storage.hpp"

namespace {

/// Background nmap job: the runner runs on its own thread so the UI stays live.
struct ScanJob {
    std::thread thread;
    vnm::NmapRunner runner;
    std::atomic<bool> finished{false};
    std::mutex mtx;
    std::string pending_log;   // human-readable events, drained by the UI thread
    std::string xml_path;      // temp file with nmap -oX output
    std::string error;
    std::string task;          // current nmap task (for the progress display)
    int percent{-1};
    std::size_t last_sig{0};   // signature of the last applied live parse
    std::size_t last_size{0};  // last observed XML file size
    std::chrono::steady_clock::time_point last_live{};
    int exit_code{-1};
};

struct App {
    GLFWwindow* window{nullptr};
    vnm::Scan scan;
    vnm::TopologyLayout layout;
    vnm::LayoutConfig config;
    vnm::ui::TopologyViewState view;

    std::vector<std::string> log;
    bool dock_built{false};

    char search_buf[128]{};
    char xml_path_buf[512]{};
    char db_path_buf[512]{};
    char export_buf[512] = "vnm_export";
    char json_path_buf[512] = "vnm_export.json";
    bool open_load_json{false};
    bool show_about{false};
    bool show_browser{false};
    std::filesystem::path browser_dir;
    std::vector<std::pair<std::string, bool>> browser_entries;
    std::string browser_error;
    int db_id{1};

    std::unique_ptr<ScanJob> scan_job;
    char target_buf[128]{};
    bool opt_service{true};
    bool opt_os{false};
    bool opt_default_scripts{false};
    bool opt_vuln_scripts{false};
    int opt_timing{4};
    std::chrono::steady_clock::time_point scan_start;

    std::unique_ptr<vnm::PassiveScanner> passive;
    std::mutex passive_mtx;
    std::map<std::string, vnm::PassiveObservation> passive_table;
    std::vector<vnm::CaptureDevice> passive_devices;
    int passive_device_index{0};
};

void log_line(App& app, const std::string& message) {
    if (std::getenv("VNM_DEBUG_LOG") != nullptr) {
        std::fprintf(stderr, "[log] %s\n", message.c_str());
    }
    app.log.push_back(message);
    if (app.log.size() > 1000) {
        app.log.erase(app.log.begin(), app.log.begin() + 200);
    }
}

void refresh(App& app) {
    app.layout = vnm::layout_scan(app.scan, app.config);
    app.view.fit_requested = true;
    app.view.selected = -1;
    app.view.cards.clear();
    app.view.node_pos.clear();
    log_line(app, "Loaded scan: " + std::to_string(app.scan.host_count()) + " host(s), " +
                      std::to_string(app.layout.clusters.size()) + " subnet(s)");
}

/// Apply a (possibly partial) scan parsed live during a running scan, keeping
/// the camera, open cards and frozen node positions.
void apply_live_scan(App& app, vnm::Scan scan) {
    if (scan.hosts.empty()) {
        return;
    }
    const bool was_empty = app.scan.hosts.empty();
    app.scan = std::move(scan);
    app.layout = vnm::layout_scan(app.scan, app.config);

    std::unordered_map<std::string, bool> present;
    present.reserve(app.scan.hosts.size());
    for (const auto& host : app.scan.hosts) {
        present[host.address] = true;
    }
    app.view.cards.erase(
        std::remove_if(app.view.cards.begin(), app.view.cards.end(),
                       [&](const vnm::ui::TopologyViewState::Card& c) {
                           return present.find(c.address) == present.end();
                       }),
        app.view.cards.end());
    if (app.view.selected >= 0 &&
        static_cast<std::size_t>(app.view.selected) >= app.scan.hosts.size()) {
        app.view.selected = -1;
    }
    if (was_empty) {
        app.view.fit_requested = true; // first hosts -> fit once
    }
}

std::size_t scan_signature(const vnm::Scan& scan) {
    std::size_t sig = scan.hosts.size() * 7 + 1;
    for (const auto& host : scan.hosts) {
        sig = sig * 31 + host.open_port_count();
    }
    return sig;
}

bool load_json(App& app, const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        log_line(app, "error: cannot read " + path);
        return false;
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    vnm::Scan scan;
    std::string error;
    if (!vnm::import_scan_json(ss.str(), scan, &error)) {
        log_line(app, "error: " + error);
        return false;
    }
    if (scan.hosts.empty()) {
        log_line(app, "error: no hosts in " + path);
        return false;
    }
    app.scan = std::move(scan);
    refresh(app);
    return true;
}

// ------------------------------------------------------------ file browser

void browser_refresh(App& app) {
    app.browser_entries.clear();
    app.browser_error.clear();
    std::error_code ec;
    std::filesystem::directory_iterator it(app.browser_dir, ec);
    if (ec) {
        app.browser_error = ec.message();
        return;
    }
    for (const auto& entry : it) {
        std::error_code entry_ec;
        const bool is_dir = entry.is_directory(entry_ec);
        const std::string name = entry.path().filename().string();
        if (is_dir) {
            app.browser_entries.emplace_back(name, true);
        } else if (entry.path().extension() == ".json") {
            app.browser_entries.emplace_back(name, false);
        }
    }
    std::sort(app.browser_entries.begin(), app.browser_entries.end(),
              [](const auto& a, const auto& b) {
                  if (a.second != b.second) {
                      return a.second > b.second; // directories first
                  }
                  return a.first < b.first;
              });
}

void open_browser(App& app, const std::string& initial) {
    std::error_code ec;
    const std::filesystem::path path(initial);
    const std::filesystem::path parent = path.has_parent_path() ? path.parent_path()
                                                                : std::filesystem::path();
    if (!parent.empty() && std::filesystem::is_directory(parent, ec)) {
        app.browser_dir = parent;
    } else {
        app.browser_dir = std::filesystem::current_path(ec);
        if (ec) {
            app.browser_dir = ".";
        }
    }
    browser_refresh(app);
    app.show_browser = true;
}

void draw_browser(App& app) {
    if (!app.show_browser) {
        return;
    }
    if (!ImGui::IsPopupOpen("Browse JSON")) {
        ImGui::OpenPopup("Browse JSON");
    }
    if (!ImGui::BeginPopupModal("Browse JSON", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        return;
    }

    bool close = false;
    ImGui::Text("Folder: %s", app.browser_dir.string().c_str());
    if (ImGui::Button("Up")) {
        const std::filesystem::path parent = app.browser_dir.parent_path();
        if (!parent.empty() && parent != app.browser_dir) {
            app.browser_dir = parent;
            browser_refresh(app);
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Refresh")) {
        browser_refresh(app);
    }
    if (!app.browser_error.empty()) {
        ImGui::TextColored(ImVec4(0.91f, 0.30f, 0.24f, 1.0f), "%s",
                           app.browser_error.c_str());
    }

    ImGui::BeginChild("##browse_list", ImVec2(560.0f, 320.0f), true);
    for (const auto& entry : app.browser_entries) {
        const bool is_dir = entry.second;
        const std::string label = std::string(is_dir ? "[DIR] " : "      ") + entry.first;
        if (ImGui::Selectable(label.c_str())) {
            if (is_dir) {
                app.browser_dir /= entry.first;
                browser_refresh(app);
                break;
            }
            const std::string full = (app.browser_dir / entry.first).string();
            std::snprintf(app.json_path_buf, sizeof(app.json_path_buf), "%s", full.c_str());
            load_json(app, full);
            close = true;
        }
    }
    ImGui::EndChild();

    ImGui::SetNextItemWidth(460.0f);
    ImGui::InputText("##browse_path", app.json_path_buf, sizeof(app.json_path_buf));
    if (ImGui::Button("Load", ImVec2(110.0f, 0.0f))) {
        load_json(app, app.json_path_buf);
        close = true;
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(110.0f, 0.0f))) {
        close = true;
    }

    if (close) {
        app.show_browser = false;
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

bool load_xml(App& app, const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        log_line(app, "error: cannot read " + path);
        return false;
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    vnm::Scan scan = vnm::NmapXmlParser::parse(ss.str());
    if (scan.hosts.empty() && scan.nmap_version.empty()) {
        log_line(app, "error: no parseable Nmap XML in " + path);
        return false;
    }
    app.scan = std::move(scan);
    refresh(app);
    return true;
}

bool load_db(App& app, const std::string& path, int id) {
    vnm::Storage storage(path);
    std::string error;
    if (!storage.open(&error)) {
        log_line(app, "error: " + error);
        return false;
    }
    const auto scan = storage.load_scan(id, &error);
    if (!scan.has_value()) {
        log_line(app, "error: " + error);
        return false;
    }
    app.scan = *scan;
    refresh(app);
    return true;
}

void init_default_target(App& app) {
    for (const auto& iface : vnm::NetInfo::interfaces()) {
        if (!iface.loopback && iface.has_ipv4 && !iface.cidr.empty()) {
            std::snprintf(app.target_buf, sizeof(app.target_buf), "%s", iface.cidr.c_str());
            return;
        }
    }
    std::snprintf(app.target_buf, sizeof(app.target_buf), "%s", "192.168.0.1/24");
}

std::string make_temp_xml() {
    const std::filesystem::path dir = std::filesystem::temp_directory_path();
    const std::string name =
        "vnm_scan_" + std::to_string(vnm::process_id()) + "_" +
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) +
        ".xml";
    return (dir / name).string();
}

void start_scan(App& app) {
    if (app.scan_job) {
        return;
    }
    const std::string target = app.target_buf;
    if (target.empty()) {
        log_line(app, "error: empty scan target");
        return;
    }

    vnm::ScanOptions options;
    options.target = target;
    options.service_detection = app.opt_service;
    options.os_detection = app.opt_os;
    options.default_scripts = app.opt_default_scripts;
    options.vuln_scripts = app.opt_vuln_scripts;
    options.timing = app.opt_timing;
    options.xml_path = make_temp_xml();  // XML to file -> normal text stays live
    options.extra_args.push_back("-v");  // verbose: discovery/open-port messages
    options.extra_args.push_back("--stats-every");
    options.extra_args.push_back("5s");

    auto job = std::make_unique<ScanJob>();
    ScanJob* raw = job.get();
    raw->xml_path = options.xml_path;
    app.scan_start = std::chrono::steady_clock::now();
    log_line(app, "Scan started: " + target);

    raw->thread = std::thread([raw, options]() {
        auto emit = [raw](const std::string& message) {
            std::lock_guard<std::mutex> lock(raw->mtx);
            raw->pending_log.append(message);
            raw->pending_log.push_back('\n');
        };
        auto set_progress = [raw](const std::string& task) {
            std::lock_guard<std::mutex> lock(raw->mtx);
            raw->task = task;
            raw->percent = -1;
        };

        const vnm::ProcessResult result = raw->runner.run(
            options, [&](std::string_view line_view) {
                std::string line(line_view);
                while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) {
                    line.pop_back();
                }
                if (line.empty()) {
                    return;
                }
                if (line.rfind("Stats:", 0) == 0) {
                    set_progress(line); // live "Stats: ... hosts completed ..."
                }
                emit(line);
            });

        {
            std::lock_guard<std::mutex> lock(raw->mtx);
            raw->error = result.error;
            raw->task.clear();
            raw->percent = -1;
        }
        raw->exit_code = result.exit_code;
        raw->finished.store(true);
    });

    app.scan_job = std::move(job);
}

void poll_scan(App& app) {
    if (!app.scan_job) {
        return;
    }
    ScanJob* job = app.scan_job.get();

    {
        std::string chunk;
        {
            std::lock_guard<std::mutex> lock(job->mtx);
            chunk.swap(job->pending_log);
        }
        std::size_t start = 0;
        while (start < chunk.size()) {
            const std::size_t nl = chunk.find('\n', start);
            if (nl == std::string::npos) {
                log_line(app, chunk.substr(start));
                break;
            }
            if (nl > start) {
                log_line(app, chunk.substr(start, nl - start));
            }
            start = nl + 1;
        }
    }

    if (!job->finished.load()) {
        // Live update: while nmap runs, re-parse the growing XML file and fold
        // newly discovered hosts onto the canvas.
        const auto now = std::chrono::steady_clock::now();
        if (now - job->last_live >= std::chrono::milliseconds(700) &&
            !job->xml_path.empty()) {
            job->last_live = now;
            std::error_code ec;
            const std::uintmax_t size = std::filesystem::file_size(job->xml_path, ec);
            if (!ec && size != job->last_size) {
                job->last_size = static_cast<std::size_t>(size);
                std::ifstream in(job->xml_path, std::ios::binary);
                if (in) {
                    std::ostringstream ss;
                    ss << in.rdbuf();
                    vnm::Scan live = vnm::NmapXmlParser::parse(ss.str());
                    const std::size_t sig = scan_signature(live);
                    if (!live.hosts.empty() && sig != job->last_sig) {
                        job->last_sig = sig;
                        apply_live_scan(app, std::move(live));
                        log_line(app, "live: " + std::to_string(app.scan.host_count()) +
                                          " host(s)");
                    }
                }
            }
        }
        return;
    }
    if (job->thread.joinable()) {
        job->thread.join();
    }

    const std::string error = job->error;
    std::string xml;
    if (!job->xml_path.empty()) {
        std::ifstream in(job->xml_path, std::ios::binary);
        if (in) {
            std::ostringstream ss;
            ss << in.rdbuf();
            xml = ss.str();
        }
        std::error_code ec;
        std::filesystem::remove(job->xml_path, ec);
    }
    if (!error.empty()) {
        log_line(app, "scan error: " + error);
    }
    if (!xml.empty()) {
        vnm::Scan scan = vnm::NmapXmlParser::parse(xml);
        if (scan.hosts.empty() && scan.nmap_version.empty()) {
            log_line(app, "error: could not parse scan output");
        } else {
            const std::size_t hosts = scan.host_count();
            const bool was_empty = app.scan.hosts.empty();
            apply_live_scan(app, std::move(scan));
            if (was_empty) {
                refresh(app); // fresh (non-live) result: fit and reset view
            }
            log_line(app, "Scan finished: " + std::to_string(hosts) + " host(s)");
        }
    } else {
        log_line(app, "scan produced no output");
    }
    app.scan_job.reset();
}

void start_passive(App& app) {
    if (app.passive) {
        return;
    }
    if (!vnm::PassiveScanner::supported()) {
        log_line(app, "passive discovery not available (built without libpcap/Npcap)");
        return;
    }
    if (app.passive_devices.empty()) {
        log_line(app, "passive: no capture device available");
        return;
    }
    const std::string device =
        app.passive_devices[static_cast<std::size_t>(app.passive_device_index)].name;
    {
        std::lock_guard<std::mutex> lock(app.passive_mtx);
        app.passive_table.clear();
    }

    auto scanner = std::make_unique<vnm::PassiveScanner>();
    App* self = &app;
    std::string error;
    const bool ok = scanner->start(
        device,
        [self](const vnm::PassiveObservation& obs) {
            std::lock_guard<std::mutex> lock(self->passive_mtx);
            const std::string key = obs.mac.empty() ? obs.ip : obs.mac;
            auto& entry = self->passive_table[key];
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
        },
        &error);
    if (!ok) {
        log_line(app, "passive: " + error);
        return;
    }
    app.passive = std::move(scanner);
    log_line(app, "Passive discovery started on " + device);
}

void stop_passive(App& app) {
    if (!app.passive) {
        return;
    }
    app.passive->stop();
    app.passive.reset();
    log_line(app, "Passive discovery stopped");
}

void merge_passive(App& app) {
    std::size_t added = 0;
    std::size_t updated = 0;
    {
        std::lock_guard<std::mutex> lock(app.passive_mtx);
        for (const auto& item : app.passive_table) {
            const vnm::PassiveObservation& o = item.second;
            if (o.ip.empty() && o.mac.empty()) {
                continue;
            }
            const std::string address = o.ip.empty() ? o.mac : o.ip;

            vnm::Host* target = nullptr;
            for (auto& host : app.scan.hosts) {
                const bool ip_match = !o.ip.empty() && host.address == o.ip;
                const bool mac_match =
                    !o.mac.empty() && !host.mac.empty() && host.mac == o.mac;
                if (ip_match || mac_match) {
                    target = &host;
                    break;
                }
            }

            if (target == nullptr) {
                vnm::Host host;
                host.address = address;
                host.mac = o.mac;
                host.hostname = o.hostname;
                host.vendor = o.vendor;
                host.status = vnm::HostStatus::Up;
                host.status_reason = "passive";
                host.subnet = o.ip.empty() ? std::string("passive")
                                           : vnm::subnet_of(o.ip, 24);
                if (host.subnet.empty()) {
                    host.subnet = "passive";
                }
                host.risk = vnm::evaluate_risk(host);
                app.scan.hosts.push_back(std::move(host));
                ++added;
            } else {
                if (target->mac.empty() && !o.mac.empty()) {
                    target->mac = o.mac;
                }
                if (target->hostname.empty() && !o.hostname.empty()) {
                    target->hostname = o.hostname;
                }
                if (target->vendor.empty() && !o.vendor.empty()) {
                    target->vendor = o.vendor;
                }
                if (target->status != vnm::HostStatus::Up) {
                    target->status = vnm::HostStatus::Up;
                    target->status_reason = "passive";
                }
                ++updated;
            }
        }
    }
    refresh(app);
    log_line(app, "Passive merge: +" + std::to_string(added) + " new, " +
                      std::to_string(updated) + " updated");
}

void build_dockspace(App& app) {
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);
    ImGui::SetNextWindowViewport(vp->ID);

    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse |
                             ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
                             ImGuiWindowFlags_NoBringToFrontOnFocus |
                             ImGuiWindowFlags_NoNavFocus | ImGuiWindowFlags_MenuBar |
                             ImGuiWindowFlags_NoDocking;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
    ImGui::Begin("##DockHost", nullptr, flags);
    ImGui::PopStyleVar(3);

    const ImGuiID dockspace_id = ImGui::GetID("VnmDockSpace");
    if (!app.dock_built) {
        app.dock_built = true;
        ImGui::DockBuilderRemoveNode(dockspace_id);
        ImGui::DockBuilderAddNode(dockspace_id, ImGuiDockNodeFlags_DockSpace);
        ImGui::DockBuilderSetNodeSize(dockspace_id, vp->WorkSize);
        ImGuiID center = dockspace_id;
        ImGuiID left = ImGui::DockBuilderSplitNode(center, ImGuiDir_Left, 0.22f,
                                                   nullptr, &center);
        ImGuiID right = ImGui::DockBuilderSplitNode(center, ImGuiDir_Right, 0.34f,
                                                    nullptr, &center);
        ImGuiID right_top = 0;
        ImGuiID right_bottom = 0;
        ImGui::DockBuilderSplitNode(right, ImGuiDir_Up, 0.50f, &right_top, &right_bottom);
        ImGuiID bottom = ImGui::DockBuilderSplitNode(center, ImGuiDir_Down, 0.26f,
                                                     nullptr, &center);
        ImGui::DockBuilderDockWindow("Passive", left);
        ImGui::DockBuilderDockWindow("Scan", right_top);
        ImGui::DockBuilderDockWindow("Inspector", right_bottom);
        ImGui::DockBuilderDockWindow("Data", right_bottom);
        ImGui::DockBuilderDockWindow("Canvas", center);
        ImGui::DockBuilderDockWindow("Log", bottom);
        ImGui::DockBuilderFinish(dockspace_id);
    }
    ImGui::DockSpace(dockspace_id, ImVec2(0.0f, 0.0f), ImGuiDockNodeFlags_None);

    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Load JSON...")) {
                app.open_load_json = true;
            }
            if (ImGui::MenuItem("Quit")) {
                glfwSetWindowShouldClose(app.window, GLFW_TRUE);
            }
            ImGui::EndMenu();
        }
        if (ImGui::MenuItem("About")) {
            app.show_about = true;
        }
        ImGui::EndMenuBar();
    }

    if (app.open_load_json) {
        ImGui::OpenPopup("Load JSON");
        app.open_load_json = false;
    }
    if (ImGui::BeginPopupModal("Load JSON", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextUnformatted("Load a previously exported JSON map:");
        ImGui::SetNextItemWidth(460.0f);
        ImGui::InputText("##json_path", app.json_path_buf, sizeof(app.json_path_buf));
        if (ImGui::Button("Browse...", ImVec2(120.0f, 0.0f))) {
            open_browser(app, app.json_path_buf);
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Load", ImVec2(120.0f, 0.0f))) {
            load_json(app, app.json_path_buf);
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(120.0f, 0.0f))) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    if (app.show_about) {
        ImGui::OpenPopup("About");
        app.show_about = false;
    }
    if (ImGui::BeginPopupModal("About", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextUnformatted("VNM - Visual Network Mapper");
        ImGui::Text("Version: %s", VNM_VERSION);
        ImGui::Separator();
        ImGui::TextUnformatted("Author: brodatech");
        ImGui::TextLinkOpenURL("brodatech.pl", "https://brodatech.pl");
        ImGui::TextLinkOpenURL("github.com/brodatech-lab", "https://github.com/brodatech-lab");
        ImGui::Separator();
        if (ImGui::Button("Close", ImVec2(120.0f, 0.0f))) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    draw_browser(app);
    ImGui::End();
}

void draw_scan_panel(App& app) {
    ImGui::Begin("Scan");
    const bool running = app.scan_job != nullptr;

    ImGui::TextWrapped("Enter a target and press Scan. The scan runs in the "
                       "background; results replace the current map.");
    ImGui::InputTextWithHint("##target", "192.168.0.1/24", app.target_buf,
                             sizeof(app.target_buf));
    ImGui::Checkbox("Service detection (-sV)", &app.opt_service);
    ImGui::Checkbox("OS detection (-O, needs setcap/root)", &app.opt_os);
    ImGui::Checkbox("Default scripts (-sC)", &app.opt_default_scripts);
    ImGui::Checkbox("Vuln scripts (--script default,vuln)", &app.opt_vuln_scripts);
    ImGui::SetNextItemWidth(90.0f);
    ImGui::InputInt("Timing (-T0..5)", &app.opt_timing);
    app.opt_timing = std::min(std::max(app.opt_timing, 0), 5);

    if (running) {
        ImGui::BeginDisabled();
    }
    if (ImGui::Button("Scan", ImVec2(120.0f, 0.0f))) {
        start_scan(app);
    }
    if (running) {
        ImGui::EndDisabled();
    }

    ImGui::SameLine();
    if (!running) {
        ImGui::BeginDisabled();
    }
    if (ImGui::Button("Cancel")) {
        if (app.scan_job) {
            app.scan_job->runner.cancel();
        }
    }
    if (!running) {
        ImGui::EndDisabled();
    }

    if (running) {
        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                                 std::chrono::steady_clock::now() - app.scan_start)
                                 .count();
        std::string task;
        int percent = -1;
        {
            std::lock_guard<std::mutex> lock(app.scan_job->mtx);
            task = app.scan_job->task;
            percent = app.scan_job->percent;
        }
        if (percent >= 0 && !task.empty()) {
            ImGui::TextColored(ImVec4(0.95f, 0.77f, 0.06f, 1.0f), "Scanning... %d%%  (%s)",
                               percent, task.c_str());
        } else if (!task.empty()) {
            ImGui::TextColored(ImVec4(0.95f, 0.77f, 0.06f, 1.0f), "Scanning... %s",
                               task.c_str());
        } else {
            ImGui::TextColored(ImVec4(0.95f, 0.77f, 0.06f, 1.0f), "Scanning... %llds",
                               static_cast<long long>(elapsed));
        }
        ImGui::Text("Hosts found: %zu", static_cast<std::size_t>(app.scan.host_count()));
    } else {
        ImGui::TextDisabled("Idle");
    }
    ImGui::End();
}

void draw_passive_panel(App& app) {
    ImGui::Begin("Passive");
    const bool running = app.passive && app.passive->running();

    ImGui::TextWrapped("Passive ARP/DHCP discovery. Needs CAP_NET_RAW (root or "
                       "setcap) on Linux; Npcap on Windows.");

    auto device_label = [](const vnm::CaptureDevice& dev) {
        return dev.description.empty() ? dev.name : dev.description;
    };
    if (!app.passive_devices.empty()) {
        if (running) {
            ImGui::BeginDisabled();
        }
        const std::string current =
            device_label(app.passive_devices[static_cast<std::size_t>(app.passive_device_index)]);
        if (ImGui::BeginCombo("Interface", current.c_str())) {
            for (int i = 0; i < static_cast<int>(app.passive_devices.size()); ++i) {
                const bool selected = i == app.passive_device_index;
                const std::string label = device_label(
                    app.passive_devices[static_cast<std::size_t>(i)]);
                if (ImGui::Selectable(label.c_str(), selected)) {
                    app.passive_device_index = i;
                }
                if (selected) {
                    ImGui::SetItemDefaultFocus();
                }
            }
            ImGui::EndCombo();
        }
        if (running) {
            ImGui::EndDisabled();
        }
    } else {
        ImGui::TextDisabled("no capture devices");
    }

    if (!running) {
        if (ImGui::Button("Start")) {
            start_passive(app);
        }
    } else if (ImGui::Button("Stop")) {
        stop_passive(app);
    }
    ImGui::SameLine();
    if (ImGui::Button("Merge to map")) {
        merge_passive(app);
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear")) {
        std::lock_guard<std::mutex> lock(app.passive_mtx);
        app.passive_table.clear();
    }

    if (app.passive && app.passive->running()) {
        ImGui::TextColored(ImVec4(0.95f, 0.77f, 0.06f, 1.0f), "Listening... packets: %llu",
                           static_cast<unsigned long long>(app.passive->packets()));
    } else if (!vnm::PassiveScanner::supported()) {
        ImGui::TextDisabled("not available (no libpcap/Npcap at build time)");
    }

    if (ImGui::BeginTable("passive_hosts", 4,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_ScrollY |
                              ImGuiTableFlags_SizingStretchProp,
                          ImVec2(0.0f, -1.0f))) {
        ImGui::TableSetupColumn("IP");
        ImGui::TableSetupColumn("MAC");
        ImGui::TableSetupColumn("Hostname");
        ImGui::TableSetupColumn("Vendor");
        ImGui::TableHeadersRow();
        std::lock_guard<std::mutex> lock(app.passive_mtx);
        for (const auto& item : app.passive_table) {
            const vnm::PassiveObservation& o = item.second;
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextUnformatted(o.ip.empty() ? "-" : o.ip.c_str());
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(o.mac.empty() ? "-" : o.mac.c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(o.hostname.empty() ? "-" : o.hostname.c_str());
            ImGui::TableSetColumnIndex(3);
            ImGui::TextUnformatted(o.vendor.empty() ? "-" : o.vendor.c_str());
        }
        ImGui::EndTable();
    }
    ImGui::End();
}

void draw_canvas(App& app) {
    ImGui::Begin("Canvas");

    if (ImGui::Button("Fit")) {
        app.view.fit_requested = true;
    }
    ImGui::SameLine();
    ImGui::Text("zoom %.0f%%", static_cast<double>(app.view.zoom * 100.0f));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(220.0f);
    if (ImGui::InputTextWithHint("##search", "search: ip, host, vendor, port:22",
                                 app.search_buf, sizeof(app.search_buf))) {
        app.view.search = app.search_buf;
    }
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.18f, 0.80f, 0.44f, 1.0f), "safe");
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.95f, 0.77f, 0.06f, 1.0f), "warning");
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.91f, 0.30f, 0.24f, 1.0f), "critical");
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.50f, 0.55f, 0.55f, 1.0f), "offline");

    ImGui::SameLine();
    bool only_responsive = app.config.only_responsive;
    if (ImGui::Checkbox("Only responding", &only_responsive)) {
        app.config.only_responsive = only_responsive;
        app.layout = vnm::layout_scan(app.scan, app.config);
        app.view.fit_requested = true;
    }

    app.view.selected = vnm::ui::draw_topology(app.scan, app.layout, app.config, app.view);

    ImGui::End();
}

void draw_host_details(const vnm::Host& host) {
    ImGui::Text("%s", host.address.c_str());
    ImGui::Separator();

    ImGui::Text("Hostname:   %s", host.hostname.empty() ? "-" : host.hostname.c_str());
    ImGui::Text("Vendor:     %s", host.vendor.empty() ? "-" : host.vendor.c_str());
    ImGui::Text("MAC:        %s", host.mac.empty() ? "-" : host.mac.c_str());
    ImGui::Text("Subnet:     %s", host.subnet.empty() ? "-" : host.subnet.c_str());
    const std::string status =
        std::string(vnm::to_string(host.status)) +
        (host.status_reason.empty() ? "" : " (" + host.status_reason + ")");
    ImGui::Text("Status:     %s", status.c_str());
    ImGui::Text("OS:         %s%s", host.os_name.empty() ? "-" : host.os_name.c_str(),
                host.os_confidence > 0
                    ? (" (" + std::to_string(host.os_confidence) + "%)").c_str()
                    : "");
    ImGui::TextColored(ImVec4(0.7f, 0.75f, 0.8f, 1.0f), "Risk:       %s",
                       vnm::to_string(host.risk));

    ImGui::Separator();
    ImGui::Text("Open ports: %zu", static_cast<std::size_t>(host.open_port_count()));
    if (ImGui::BeginTable("ports", 5,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_SizingStretchProp)) {
        ImGui::TableSetupColumn("Port");
        ImGui::TableSetupColumn("State");
        ImGui::TableSetupColumn("Service");
        ImGui::TableSetupColumn("Version");
        ImGui::TableSetupColumn("Links");
        ImGui::TableHeadersRow();
        for (const auto& port : host.ports) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("%u/%s", static_cast<unsigned>(port.number), port.protocol.c_str());
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(port.state.c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(port.service.c_str());
            ImGui::TableSetColumnIndex(3);
            const std::string version =
                port.product + (port.version.empty() ? "" : " " + port.version);
            ImGui::TextUnformatted(version.c_str());
            ImGui::TableSetColumnIndex(4);
            if (port.state == "open") {
                const std::vector<vnm::RefLink> links = vnm::port_links(host, port);
                bool first = true;
                for (const auto& link : links) {
                    if (!first) {
                        ImGui::SameLine();
                    }
                    first = false;
                    ImGui::TextLinkOpenURL(link.label.c_str(), link.url.c_str());
                }
            }
        }
        ImGui::EndTable();
    }

    const std::vector<vnm::RefLink> host_refs = vnm::host_links(host);
    if (!host_refs.empty()) {
        ImGui::Separator();
        ImGui::Text("Host CVEs:");
        bool first = true;
        for (const auto& link : host_refs) {
            if (!first) {
                ImGui::SameLine();
            }
            first = false;
            ImGui::TextLinkOpenURL(link.label.c_str(), link.url.c_str());
        }
    }
}

void draw_inspector(App& app) {
    ImGui::Begin("Inspector");
    const int sel = app.view.selected;
    if (sel < 0 || static_cast<std::size_t>(sel) >= app.scan.hosts.size()) {
        ImGui::TextUnformatted("Select a host on the map.");
        ImGui::End();
        return;
    }
    draw_host_details(app.scan.hosts[static_cast<std::size_t>(sel)]);
    ImGui::End();
}

void do_export(App& app, const char* ext) {
    const std::string path = std::string(app.export_buf) + "." + ext;
    const vnm::ExportFormat format = vnm::parse_format(ext);
    std::string error;
    if (vnm::export_scan(app.scan, app.layout, format, path, &error)) {
        log_line(app, "Exported " + std::to_string(app.scan.host_count()) +
                          " host(s) to " + path);
    } else {
        log_line(app, "export error: " + error);
    }
}

void draw_data(App& app) {
    ImGui::Begin("Data");

    ImGui::TextWrapped("Load a scan from an Nmap XML file or from the local database.");
    ImGui::Separator();

    ImGui::InputText("XML path", app.xml_path_buf, sizeof(app.xml_path_buf));
    if (ImGui::Button("Load XML")) {
        load_xml(app, app.xml_path_buf);
    }

    ImGui::Separator();
    ImGui::InputText("DB path", app.db_path_buf, sizeof(app.db_path_buf));
    ImGui::InputInt("Scan id", &app.db_id);
    if (ImGui::Button("Load from DB")) {
        load_db(app, app.db_path_buf, app.db_id);
    }

    ImGui::Separator();
    ImGui::InputText("JSON path", app.json_path_buf, sizeof(app.json_path_buf));
    if (ImGui::Button("Browse...")) {
        open_browser(app, app.json_path_buf);
    }
    ImGui::SameLine();
    if (ImGui::Button("Load JSON")) {
        load_json(app, app.json_path_buf);
    }

    ImGui::Separator();
    ImGui::TextWrapped("Export the current map (base path + format extension):");
    ImGui::InputText("Export base", app.export_buf, sizeof(app.export_buf));
    if (ImGui::Button("SVG")) {
        do_export(app, "svg");
    }
    ImGui::SameLine();
    if (ImGui::Button("PNG")) {
        do_export(app, "png");
    }
    ImGui::SameLine();
    if (ImGui::Button("JSON")) {
        do_export(app, "json");
    }
    ImGui::End();
}

void draw_log(App& app) {
    ImGui::Begin("Log");
    ImGui::BeginChild("##log_scroll", ImVec2(0, 0), false,
                      ImGuiWindowFlags_HorizontalScrollbar);
    for (const auto& line : app.log) {
        ImGui::TextUnformatted(line.c_str());
    }
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 1.0f) {
        ImGui::SetScrollHereY(1.0f);
    }
    ImGui::EndChild();
    ImGui::End();
}

} // namespace

int main(int argc, char** argv) {
    App app;

    std::string storage_path = vnm::Storage::default_path();
    std::string xml_arg;
    int db_arg = -1;
    bool auto_scan = false;
    bool target_set = false;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--scan" && i + 1 < argc) {
            std::snprintf(app.target_buf, sizeof(app.target_buf), "%s", argv[++i]);
            auto_scan = true;
            target_set = true;
        } else if (arg == "--no-service") {
            app.opt_service = false;
        } else if (arg == "--id" && i + 1 < argc) {
            db_arg = std::atoi(argv[++i]);
        } else if (arg == "--db" && i + 1 < argc) {
            storage_path = argv[++i];
        } else {
            xml_arg = arg;
        }
    }

    std::snprintf(app.db_path_buf, sizeof(app.db_path_buf), "%s", storage_path.c_str());
    if (!xml_arg.empty()) {
        std::snprintf(app.xml_path_buf, sizeof(app.xml_path_buf), "%s", xml_arg.c_str());
    }
    if (!target_set) {
        init_default_target(app);
    }

    app.passive_devices = vnm::PassiveScanner::devices();
    if (app.passive_devices.empty()) {
        for (const auto& iface : vnm::NetInfo::interfaces()) {
            if (!iface.loopback) {
                app.passive_devices.push_back(vnm::CaptureDevice{iface.name, iface.name});
            }
        }
    }

    if (!glfwInit()) {
        std::fprintf(stderr, "error: failed to initialize GLFW\n");
        return 1;
    }
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);

    app.window = glfwCreateWindow(1360, 840, "VNM - Visual Network Mapper", nullptr, nullptr);
    if (app.window == nullptr) {
        std::fprintf(stderr, "error: failed to create window (is a display available?)\n");
        glfwTerminate();
        return 1;
    }
    glfwMakeContextCurrent(app.window);
    glfwSwapInterval(1);

    {
        constexpr int icon_size = 64;
        std::vector<unsigned char> icon_pixels(
            static_cast<std::size_t>(icon_size) * icon_size * 4);
        vnm::ui::draw_vnm_icon(icon_pixels.data(), icon_size);
        GLFWimage image;
        image.width = icon_size;
        image.height = icon_size;
        image.pixels = icon_pixels.data();
        glfwSetWindowIcon(app.window, 1, &image);
    }

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    ImGui::StyleColorsDark();
    ImGui::GetStyle().WindowRounding = 6.0f;
    ImGui::GetStyle().FrameRounding = 4.0f;

    ImGui_ImplGlfw_InitForOpenGL(app.window, true);
    ImGui_ImplOpenGL3_Init("#version 130");

    if (!xml_arg.empty()) {
        if (xml_arg.size() > 5 && xml_arg.compare(xml_arg.size() - 5, 5, ".json") == 0) {
            load_json(app, xml_arg);
        } else {
            load_xml(app, xml_arg);
        }
    } else if (db_arg > 0) {
        load_db(app, storage_path, db_arg);
    }

    if (auto_scan) {
        start_scan(app);
    }

    while (!glfwWindowShouldClose(app.window)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        poll_scan(app);

        build_dockspace(app);
        draw_scan_panel(app);
        draw_passive_panel(app);
        draw_canvas(app);
        draw_inspector(app);
        draw_data(app);
        draw_log(app);

        ImGui::Render();
        int display_w = 0;
        int display_h = 0;
        glfwGetFramebufferSize(app.window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.08f, 0.09f, 0.11f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(app.window);
    }

    if (app.passive) {
        app.passive->stop();
    }
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(app.window);
    glfwTerminate();
    return 0;
}
