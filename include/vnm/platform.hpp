#pragma once

namespace vnm {

/// Portable process id (POSIX getpid / Windows _getpid).
[[nodiscard]] unsigned long process_id();

} // namespace vnm
