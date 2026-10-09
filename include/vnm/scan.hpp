#pragma once

#include <atomic>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace vnm {

/// Parameters controlling a single nmap invocation.
struct ScanOptions {
    std::string target;                          // e.g. 192.168.1.0/24
    std::string nmap_path{"nmap"};               // resolved via PATH
    std::string xml_path;                        // if set, write XML here and
                                                 // stream nmap's normal output
                                                 // instead (readable live log)
    std::vector<std::string> extra_args;         // appended verbatim
    bool service_detection{true};                // -sV
    bool os_detection{false};                    // -O (needs privileges)
    bool default_scripts{false};                 // -sC (default NSE scripts)
    bool vuln_scripts{false};                    // --script default,vuln
    int script_timeout_seconds{60};              // --script-timeout (0 = off)
    int timing{4};                               // -T<0..5>
};

/// Outcome of a spawned process.
struct ProcessResult {
    int exit_code{-1};
    bool cancelled{false};
    std::string error;                           // empty on success
    [[nodiscard]] bool ok() const { return error.empty() && exit_code == 0; }
};

/// Runs the external `nmap` binary and streams its XML output line by line.
///
/// The runner is intentionally dependency free (no libnmap/libpcap):
/// it uses POSIX fork/exec + a pipe and hands raw lines to a callback so the
/// UI can update the map while the scan is still running.
class NmapRunner {
public:
    using LineCallback = std::function<void(std::string_view line)>;

    /// Blocking run. `on_line` is invoked for every stdout/stdin line.
    /// Returns as soon as the process exits or cancel() was requested.
    ProcessResult run(const ScanOptions& options, const LineCallback& on_line);

    /// Ask a currently running scan to stop (thread-safe).
    void cancel() noexcept { cancelled_.store(true); }

    /// Build the argv vector used for the scan (exposed for testing).
    [[nodiscard]] static std::vector<std::string> build_argv(const ScanOptions& options);

private:
    std::atomic<bool> cancelled_{false};
};

} // namespace vnm
