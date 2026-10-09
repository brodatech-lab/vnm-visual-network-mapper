#include "vnm/scan.hpp"

#include <array>
#include <cerrno>
#include <cstring>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <cstdio>
#else
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace vnm {

std::vector<std::string> NmapRunner::build_argv(const ScanOptions& options) {
    std::vector<std::string> argv;
    argv.push_back(options.nmap_path);
    argv.push_back("-oX");
    argv.push_back("-"); // XML to stdout
    argv.push_back("-T" + std::to_string(options.timing));
    if (options.service_detection) {
        argv.push_back("-sV");
    }
    if (options.os_detection) {
        argv.push_back("-O");
    }
    for (const auto& extra : options.extra_args) {
        argv.push_back(extra);
    }
    argv.push_back(options.target);
    return argv;
}

#if defined(_WIN32)

ProcessResult NmapRunner::run(const ScanOptions&, const LineCallback&) {
    return ProcessResult{-1, false, "scan runner is not implemented on Windows yet"};
}

#else

ProcessResult NmapRunner::run(const ScanOptions& options, const LineCallback& on_line) {
    ProcessResult result;
    cancelled_.store(false);

    if (options.target.empty()) {
        result.error = "no scan target supplied";
        return result;
    }

    const std::vector<std::string> argv_strings = build_argv(options);

    int pipe_fds[2] = {-1, -1};
    if (::pipe(pipe_fds) != 0) {
        result.error = std::string("pipe() failed: ") + std::strerror(errno);
        return result;
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        result.error = std::string("fork() failed: ") + std::strerror(errno);
        ::close(pipe_fds[0]);
        ::close(pipe_fds[1]);
        return result;
    }

    if (pid == 0) {
        // ---- child ----
        ::close(pipe_fds[0]);
        ::dup2(pipe_fds[1], STDOUT_FILENO);
        ::dup2(pipe_fds[1], STDERR_FILENO);
        if (pipe_fds[1] > STDERR_FILENO) {
            ::close(pipe_fds[1]);
        }

        std::vector<char*> argv;
        argv.reserve(argv_strings.size() + 1);
        for (const auto& arg : argv_strings) {
            argv.push_back(const_cast<char*>(arg.c_str()));
        }
        argv.push_back(nullptr);

        ::execvp(argv[0], argv.data());
        // exec failed
        const char* msg = "failed to execute nmap\n";
        (void)!::write(STDERR_FILENO, msg, std::strlen(msg));
        _exit(127);
    }

    // ---- parent ----
    ::close(pipe_fds[1]);

    std::string buffer;
    std::array<char, 8192> chunk{};
    bool terminated = false;

    while (!terminated) {
        if (cancelled_.load()) {
            ::kill(pid, SIGTERM);
        }

        pollfd pfd{};
        pfd.fd = pipe_fds[0];
        pfd.events = POLLIN;
        const int ready = ::poll(&pfd, 1, 200);

        if (ready == 0) {
            continue; // timeout: re-check cancellation
        }
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            result.error = std::string("poll() failed: ") + std::strerror(errno);
            break;
        }

        const ssize_t n = ::read(pipe_fds[0], chunk.data(), chunk.size());
        if (n > 0) {
            buffer.append(chunk.data(), static_cast<std::size_t>(n));
            std::size_t pos = 0;
            std::size_t nl = 0;
            while ((nl = buffer.find('\n', pos)) != std::string::npos) {
                if (on_line) {
                    on_line(std::string_view(buffer).substr(pos, nl - pos));
                }
                pos = nl + 1;
            }
            buffer.erase(0, pos);
        } else if (n == 0) {
            terminated = true; // EOF
        } else if (errno != EINTR) {
            result.error = std::string("read() failed: ") + std::strerror(errno);
            break;
        }
    }

    if (!buffer.empty() && on_line) {
        on_line(buffer);
    }

    ::close(pipe_fds[0]);

    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }

    if (WIFEXITED(status)) {
        result.exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        result.exit_code = 128 + WTERMSIG(status);
    }

    result.cancelled = cancelled_.load();
    if (result.cancelled && result.error.empty()) {
        result.error = "scan cancelled";
    } else if (!result.error.empty()) {
        // keep parser/UI informed
    } else if (result.exit_code == 127) {
        result.error = "nmap not found or not executable";
    }
    return result;
}

#endif

} // namespace vnm
