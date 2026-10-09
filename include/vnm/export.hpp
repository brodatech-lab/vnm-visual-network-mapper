#pragma once

#include <string>

#include "vnm/layout.hpp"
#include "vnm/model.hpp"

namespace vnm {

/// Supported export formats.
enum class ExportFormat { Svg, Png, Json };

[[nodiscard]] const char* to_string(ExportFormat format) noexcept;

/// Parse "svg" / "png" / "json" (case-sensitive). Sets *ok when provided.
[[nodiscard]] ExportFormat parse_format(const std::string& text, bool* ok = nullptr);

/// Render `scan` using its `layout` to `path`. Returns false + *error on failure.
bool export_scan(const Scan& scan, const TopologyLayout& layout, ExportFormat format,
                 const std::string& path, std::string* error = nullptr);

/// Parse JSON produced by export_scan(ExportFormat::Json) back into a Scan.
bool import_scan_json(const std::string& text, Scan& out, std::string* error = nullptr);

} // namespace vnm
