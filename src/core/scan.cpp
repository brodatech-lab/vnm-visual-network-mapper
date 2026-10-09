#include "vnm/scan.hpp"

#include <array>
#include <cerrno>
#include <cstring>
#include <string>
#include <vector>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
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
    if (!options.xml_path.empty()) {
        // XML to file so nmap keeps its normal (human-readable) output live
        // on the pipe for the UI log.
        argv.push_back("-oX");
        argv.push_back(options.xml_path);
    } else {
        argv.push_back("-oX");
        argv.push_back("-"); // XML to stdout
    }
    argv.push_back("-T" + std::to_string(options.timing));
    if (options.service_detection) {
        argv.push_back("-sV");
    }
    if (options.os_detection) {
        argv.push_back("-O");
    }
    if (options.vuln_scripts) {
        argv.push_back("--script");
        argv.push_back("default,vuln");
    } else if (options.default_scripts) {
        argv.push_back("-sC");
    }
    for (const auto& extra : options.extra_args) {
        argv.push_back(extra);
    }
    argv.push_back(options.target);
    return argv;
}

#if defined(_WIN32)

namespace {

/// Quote one argument for the Windows command line (CommandLineToArgvW rules).
std::string quote_arg(const std::string& arg) {
    if (!arg.empty() && arg.find_first_of(" \t\"") == std::string::npos) {
        return arg;
    }
    std::string out = "\"";
    std::size_t backslashes = 0;
    for (const char c : arg) {
        if (c == '\\') {
            ++backslashes;
        } else if (c == '"') {
            out.append(backslashes * 2 + 1, '\\');
            out.push_back('"');
            backslashes = 0;
        } else {
            out.append(backslashes, '\\');
            backslashes = 0;
            out.push_back(c);
        }
    }
    out.append(backslashes * 2, '\\');
    out.push_back('"');
    return out;
}

std::string build_command_line(const std::vector<std::string>& argv) {
    std::string cmdline;
    for (std::size_t i = 0; i < argv.size(); ++i) {
        if (i != 0) {
            cmdline.push_back(' ');
        }
        cmdline += quote_arg(argv[i]);
    }
    return cmdline;
}

} // namespace

ProcessResult NmapRunner::run(const ScanOptions& options, const LineCallback& on_line) {
    ProcessResult result;
    cancelled_.store(false);

    if (options.target.empty()) {
        result.error = "no scan target supplied";
        return result;
    }

    const std::vector<std::string> argv = build_argv(options);
    std::string cmdline = build_command_line(argv);
    std::vector<char> mutable_cmd(cmdline.begin(), cmdline.end());
    mutable_cmd.push_back('\0');

    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE read_pipe = nullptr;
    HANDLE write_pipe = nullptr;
    if (!CreatePipe(&read_pipe, &write_pipe, &sa, 0)) {
        result.error = "CreatePipe() failed";
        return result;
    }
    SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = write_pipe;
    startup.hStdError = write_pipe;

    PROCESS_INFORMATION process{};
    const BOOL created = CreateProcessA(
        nullptr, mutable_cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
        nullptr, nullptr, &startup, &process);
    CloseHandle(write_pipe);

    if (!created) {
        CloseHandle(read_pipe);
        result.error = "nmap not found or not executable";
        return result;
    }

    std::string buffer;
    std::array<char, 8192> chunk{};

    auto flush_lines = [&]() {
        std::size_t pos = 0;
        std::size_t nl = 0;
        while ((nl = buffer.find('\n', pos)) != std::string::npos) {
            std::string_view line = std::string_view(buffer).substr(pos, nl - pos);
            if (!line.empty() && line.back() == '\r') {
                line.remove_suffix(1);
            }
            if (on_line) {
                on_line(line);
            }
            pos = nl + 1;
        }
        buffer.erase(0, pos);
    };

    for (;;) {
        if (cancelled_.load()) {
            TerminateProcess(process.hProcess, 1);
        }

        DWORD available = 0;
        if (!PeekNamedPipe(read_pipe, nullptr, 0, nullptr, &available, nullptr)) {
            break; // pipe closed
        }

        if (available > 0) {
            DWORD read = 0;
            if (!ReadFile(read_pipe, chunk.data(), static_cast<DWORD>(chunk.size()),
                          &read, nullptr) ||
                read == 0) {
                break;
            }
            buffer.append(chunk.data(), read);
            flush_lines();
            continue;
        }

        const DWORD wait = WaitForSingleObject(process.hProcess, 100);
        if (wait == WAIT_OBJECT_0) {
            DWORD remaining = 0;
            if (!PeekNamedPipe(read_pipe, nullptr, 0, nullptr, &remaining, nullptr) ||
                remaining == 0) {
                break;
            }
        }
    }

    if (!buffer.empty() && on_line) {
        if (buffer.back() == '\r') {
            buffer.pop_back();
        }
        on_line(buffer);
    }

    CloseHandle(read_pipe);
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD exit_code = 0;
    GetExitCodeProcess(process.hProcess, &exit_code);
    result.exit_code = static_cast<int>(exit_code);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);

    result.cancelled = cancelled_.load();
    if (result.cancelled && result.error.empty()) {
        result.error = "scan cancelled";
    }
    return result;
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
