#include <GLFW/glfw3.h>

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "imgui_internal.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "topology_view.hpp"
#include "vnm/layout.hpp"
#include "vnm/model.hpp"
#include "vnm/parse.hpp"
#include "vnm/storage.hpp"

namespace {

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
    int db_id{1};
};

void log_line(App& app, const std::string& message) {
    app.log.push_back(message);
    if (app.log.size() > 1000) {
        app.log.erase(app.log.begin(), app.log.begin() + 200);
    }
}

void refresh(App& app) {
    app.layout = vnm::layout_scan(app.scan, app.config);
    app.view.fit_requested = true;
    app.view.selected = -1;
    log_line(app, "Loaded scan: " + std::to_string(app.scan.host_count()) + " host(s), " +
                      std::to_string(app.layout.clusters.size()) + " subnet(s)");
}

void load_demo(App& app) {
    vnm::Scan scan;
    scan.target = "demo 192.168.0.0/24 + 10.0.0.0/24";
    scan.nmap_version = "demo";

    auto add = [&](const char* address, const char* hostname, const char* vendor,
                   const char* os, int confidence, vnm::HostStatus status,
                   std::vector<vnm::Port> ports) {
        vnm::Host host;
        host.address = address;
        host.hostname = hostname;
        host.vendor = vendor;
        host.os_name = os;
        host.os_confidence = confidence;
        host.status = status;
        host.ports = std::move(ports);
        host.subnet = vnm::subnet_of(address, 24);
        host.risk = vnm::evaluate_risk(host);
        scan.hosts.push_back(std::move(host));
    };

    add("192.168.0.1", "router.lan", "TP-Link", "Linux 5.x", 96, vnm::HostStatus::Up,
        {{22, "tcp", "open", "ssh", "OpenSSH", "9.0", ""},
         {80, "tcp", "open", "http", "nginx", "1.24", ""},
         {443, "tcp", "open", "https", "nginx", "1.24", ""}});
    add("192.168.0.20", "nas.lan", "Synology", "Linux", 88, vnm::HostStatus::Up,
        {{22, "tcp", "open", "ssh", "OpenSSH", "8.9", ""},
         {445, "tcp", "open", "microsoft-ds", "Samba", "4.15", ""}});
    add("192.168.0.42", "old-printer.lan", "HP", "embedded", 60, vnm::HostStatus::Up,
        {{23, "tcp", "open", "telnet", "", "", ""},
         {80, "tcp", "open", "http", "GoAhead", "2.1", ""}});
    add("192.168.0.50", "", "Raspberry Pi", "Linux", 80, vnm::HostStatus::Up,
        {{22, "tcp", "open", "ssh", "Dropbear", "2022", ""}});
    add("192.168.0.99", "", "", "", 0, vnm::HostStatus::Down, {});
    add("10.0.0.1", "core-switch", "Cisco", "IOS", 70, vnm::HostStatus::Up,
        {{22, "tcp", "open", "ssh", "Cisco", "1.25", ""},
         {443, "tcp", "open", "https", "", "", ""}});
    add("10.0.0.5", "web", "VMware", "Linux", 84, vnm::HostStatus::Up,
        {{443, "tcp", "open", "https", "nginx", "1.24", ""}});

    app.scan = std::move(scan);
    refresh(app);
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
        ImGuiID right = ImGui::DockBuilderSplitNode(center, ImGuiDir_Right, 0.32f,
                                                    nullptr, &center);
        ImGuiID bottom = ImGui::DockBuilderSplitNode(center, ImGuiDir_Down, 0.26f,
                                                     nullptr, &center);
        ImGui::DockBuilderDockWindow("Canvas", center);
        ImGui::DockBuilderDockWindow("Inspector", right);
        ImGui::DockBuilderDockWindow("Data", right);
        ImGui::DockBuilderDockWindow("Log", bottom);
        ImGui::DockBuilderFinish(dockspace_id);
    }
    ImGui::DockSpace(dockspace_id, ImVec2(0.0f, 0.0f), ImGuiDockNodeFlags_None);

    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Load demo scan")) {
                load_demo(app);
            }
            if (ImGui::MenuItem("Quit")) {
                glfwSetWindowShouldClose(app.window, GLFW_TRUE);
            }
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("View")) {
            if (ImGui::MenuItem("Fit to view", "F")) {
                app.view.fit_requested = true;
            }
            ImGui::EndMenu();
        }
        ImGui::EndMenuBar();
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

    app.view.selected = vnm::ui::draw_topology(app.scan, app.layout, app.config, app.view);

    ImGui::End();
}

void draw_inspector(App& app) {
    ImGui::Begin("Inspector");
    const int sel = app.view.selected;
    if (sel < 0 || static_cast<std::size_t>(sel) >= app.scan.hosts.size()) {
        ImGui::TextUnformatted("Select a host on the map.");
        ImGui::End();
        return;
    }

    const vnm::Host& host = app.scan.hosts[static_cast<std::size_t>(sel)];
    ImGui::Text("%s", host.address.c_str());
    ImGui::Separator();

    ImGui::Text("Hostname:   %s", host.hostname.empty() ? "-" : host.hostname.c_str());
    ImGui::Text("Vendor:     %s", host.vendor.empty() ? "-" : host.vendor.c_str());
    ImGui::Text("MAC:        %s", host.mac.empty() ? "-" : host.mac.c_str());
    ImGui::Text("Subnet:     %s", host.subnet.empty() ? "-" : host.subnet.c_str());
    ImGui::Text("Status:     %s", vnm::to_string(host.status));
    ImGui::Text("OS:         %s%s", host.os_name.empty() ? "-" : host.os_name.c_str(),
                host.os_confidence > 0
                    ? (" (" + std::to_string(host.os_confidence) + "%)").c_str()
                    : "");
    ImGui::TextColored(ImVec4(0.7f, 0.75f, 0.8f, 1.0f), "Risk:       %s",
                       vnm::to_string(host.risk));

    ImGui::Separator();
    ImGui::Text("Open ports: %zu", static_cast<std::size_t>(host.open_port_count()));
    if (ImGui::BeginTable("ports", 4,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_SizingStretchProp)) {
        ImGui::TableSetupColumn("Port");
        ImGui::TableSetupColumn("State");
        ImGui::TableSetupColumn("Service");
        ImGui::TableSetupColumn("Version");
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
            const std::string version = port.product + (port.version.empty() ? "" : " " + port.version);
            ImGui::TextUnformatted(version.c_str());
        }
        ImGui::EndTable();
    }
    ImGui::End();
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
    ImGui::SameLine();
    if (ImGui::Button("Demo")) {
        load_demo(app);
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
    bool want_demo = (argc < 2);
    int db_arg = -1;

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--demo") {
            want_demo = true;
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
        load_xml(app, xml_arg);
    } else if (db_arg > 0) {
        load_db(app, storage_path, db_arg);
    } else if (want_demo) {
        load_demo(app);
    }

    while (!glfwWindowShouldClose(app.window)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        build_dockspace(app);
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

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(app.window);
    glfwTerminate();
    return 0;
}
