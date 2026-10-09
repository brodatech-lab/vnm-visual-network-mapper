#include "vnm/platform.hpp"

#if defined(_WIN32)
#include <process.h>
#else
#include <unistd.h>
#endif

namespace vnm {

unsigned long process_id() {
#if defined(_WIN32)
    return static_cast<unsigned long>(::_getpid());
#else
    return static_cast<unsigned long>(::getpid());
#endif
}

} // namespace vnm
