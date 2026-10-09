#pragma once

#include <string>

#include "vnm/model.hpp"

namespace vnm {

/// Incrementally folds nmap's normal (streamed) output into a Scan.
///
/// This works while the scan is running, on every platform (unlike nmap's XML
/// file, which may be locked or half-written). Down hosts ("[host down]") are
/// ignored so the live map matches the final result.
class LiveOutputParser {
public:
    void feed_line(const std::string& line);
    void reset();

    [[nodiscard]] const Scan& scan() const noexcept { return scan_; }
    [[nodiscard]] Scan& scan() noexcept { return scan_; }

private:
    int find_or_add_host(const std::string& ip);
    void add_open_port(Host& host, int number, const std::string& protocol);

    Scan scan_;
    int current_{-1};
};

} // namespace vnm
