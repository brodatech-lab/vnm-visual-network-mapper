[English](README.md) | [Polski](README.pl.md)

# VNM – Visual Network Mapper

Native desktop tool for network engineers, pentesters and homelabs. A flat,
readable 2D view of network topology (nodes, `/24` subnets, security status)
built on top of Nmap scan results.

> **Status:** `v0.2.0` – native core (engine + CLI) and an SQLite backend with
> scan history and diffing. The 2D GUI layer (Dear ImGui) is in planning.

## Why

- No Electron / web stack: sub-second startup, low RAM usage.
- Automatic clustering of hosts into `/24` subnet frames.
- Risk colouring: 🟢 safe · 🟡 warning · 🔴 critical · ⚪ offline.
- A single binary, no Node.js / Python / Docker.

## Requirements

- C++20 compiler (GCC 13+ or Clang 16+)
- CMake ≥ 3.20
- `nmap` in `PATH` (scanning)
- Optional: `nmap` + `setcap` for OS detection / SYN scans

## Quick start

Install dependencies and configure the environment (once, requires sudo):

```sh
sudo ./scripts/setup-dev.sh
```

Build and test:

```sh
cmake -S . -B build/debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build/debug -j
ctest --test-dir build/debug --output-on-failure
```

## Usage (CLI)

```sh
./build/debug/vnm interfaces              # local interfaces + default gateway
./build/debug/vnm scan 192.168.0.0/24     # run nmap, print and store hosts
./build/debug/vnm parse scan.xml --save   # parse an Nmap XML file and store it
./build/debug/vnm layout scan.xml         # compute 2D subnet clusters
./build/debug/vnm history                 # list stored scans
./build/debug/vnm show 1                  # print a stored scan
./build/debug/vnm diff 1 2                # compare two scans (time travel)
```

`scan` options: `--os`, `--no-service`, `--no-save`, `--nmap <path>`, `-T<n>`,
`--arg <value>`.

Default database: `~/.config/vnm/storage.db` (override with `VNM_DB`).

## Architecture

```
include/vnm/        public API headers
src/core/           GUI-independent core
  model.cpp         data model + risk assessment
  net.cpp           interface auto-detection (/sys/class/net, /proc/net/route)
  scan.cpp          nmap runner (POSIX fork/exec + pipe, live XML)
  parse.cpp         dependency-free Nmap XML parser
  layout.cpp        /24 subnet clustering + 2D grid layout
  diff.cpp          scan comparison (added/removed/changed)
  storage.cpp       SQLite backend (scans/hosts/ports) + history
src/cli/main.cpp    CLI bootstrap
src/ui/             planned 2D GUI target (Dear ImGui + GLFW)
tests/              unit tests (CTest)
```

`vnm_core` (static library) has no GUI dependencies, so it is testable in
isolation and can be reused by both the CLI and the future GUI.

## Roadmap

- [x] Data model, risk assessment, Nmap XML parser, CLI runner
- [x] Interface auto-detection and subnet clustering
- [x] SQLite backend (`~/.config/vnm/storage.db`) and scan diffing
- [ ] 2D GUI (Dear ImGui): canvas, minimap, inspector, docking
- [ ] Passive discovery (libpcap), SVG/PNG/PDF export

## License

To be determined.
