[English](README.md) | [Polski](README.pl.md)

# VNM – Visual Network Mapper

Native desktop tool for network engineers, pentesters and homelabs. A flat,
readable 2D view of network topology (nodes, `/24` subnets, security status)
built on top of Nmap scan results.

> **Status:** `v0.6.0` – native core (engine + CLI), SQLite history + diffing,
> a native 2D GUI (Dear ImGui docking), **Windows + Linux** support, **passive
> discovery** (ARP/DHCP) and **SVG/PNG/JSON export**.

## Why

- No Electron / web stack: sub-second startup, low RAM usage.
- Automatic clustering of hosts into `/24` subnet frames.
- Risk colouring: 🟢 safe · 🟡 warning · 🔴 critical · ⚪ offline.
- A single binary on Linux and Windows, no Node.js / Python / Docker.

## Requirements

- C++20 compiler (GCC 13+ / Clang 16+ on Linux; MSVC 2022 on Windows)
- CMake ≥ 3.20
- `nmap` in `PATH` (scanning)
- Linux: optional `setcap` for OS detection / SYN scans
- Windows: **Nmap for Windows** (bundles Npcap); run as Administrator for
  `-sS`/`-O`/ARP scans, otherwise use a connect scan (`-sT`)
- GUI: GLFW 3.3+ and OpenGL (Dear ImGui is fetched via CMake FetchContent on
  first GUI configure, so a network connection is needed once)
- Passive discovery (Linux): `libpcap` (auto-detected; needs `CAP_NET_RAW`)
- Passive discovery (Windows): install the **Npcap** driver at runtime (the
  Npcap SDK is fetched automatically at build time); run as Administrator

## Quick start (Linux)

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

## Build on Windows

With Visual Studio 2022 (MSVC) and CMake:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DVNM_BUILD_GUI=ON
cmake --build build --config Release --parallel
# binaries: build\Release\vnm.exe and build\src\ui\Release\vnm_gui.exe
```

(or use the `windows-msvc` preset). Prebuilt `.exe`/Linux binaries are produced
by the GitHub Actions release workflow on version tags.

## Usage (CLI)

```sh
./build/debug/vnm interfaces              # local interfaces + default gateway
./build/debug/vnm scan 192.168.0.0/24     # run nmap, print and store hosts
./build/debug/vnm parse scan.xml --save   # parse an Nmap XML file and store it
./build/debug/vnm layout scan.xml         # compute 2D subnet clusters
./build/debug/vnm history                 # list stored scans
./build/debug/vnm show 1                  # print a stored scan
./build/debug/vnm diff 1 2                # compare two scans (time travel)
./build/debug/vnm sniff --seconds 10      # passive ARP/DHCP discovery
./build/debug/vnm export scan.xml --format svg --out map.svg   # export the map
```

`scan` options: `--os`, `--no-service`, `--scripts` (`-sC`), `--vuln`
(`--script default,vuln`), `--no-save`, `--nmap <path>`, `-T<n>`, `--arg <value>`.

Default database: `~/.config/vnm/storage.db` (override with `VNM_DB`).

## GUI (2D map)

Build with `-DVNM_BUILD_GUI=ON` and launch `vnm_gui`:

```sh
cmake -S . -B build/debug -DVNM_BUILD_GUI=ON
cmake --build build/debug -j
./build/debug/src/ui/vnm_gui                 # empty canvas
./build/debug/src/ui/vnm_gui scan.xml        # load an Nmap XML file
./build/debug/src/ui/vnm_gui map.json        # load an exported JSON map
./build/debug/src/ui/vnm_gui --id 1          # load scan #1 from the database
./build/debug/src/ui/vnm_gui --scan 192.168.0.1/24   # start a scan immediately
```

Use **File → Load JSON…** (with a native file browser) to bring a previously
exported map back onto the canvas. **About** shows the version and links.

Features: docked panels (Canvas / Inspector / Scan / Data / Log), pan & zoom, fit
to view, subnet frames, risk colouring, minimap with viewport, click-to-inspect
with a ports table, and search (`ip`, `host`, `vendor` or `port:22`). The map
only shows responding hosts (toggle **Only responding**); addresses nmap assumed
up without a reply are hidden.

The **Scan** panel runs `nmap` in the background only after you press **Scan**
(target, `-sV`, `-O`, timing; with a **Cancel** button and a verbose,
human-readable log of nmap's native output — initiating scans, discovered open
ports, per-host reports). Results replace the map when the scan finishes, and
the map is **built live** while the scan runs (new hosts/ports appear as they are
discovered; the camera and node positions are preserved).

The **Passive** panel listens for ARP/DHCP traffic (needs `CAP_NET_RAW` on
Linux) and lists observed hosts; **Merge to map** folds them into the topology.

Each host detail card (and the Inspector) shows clickable **reference links**
for open ports: port info (SpeedGuide/IANA/Shodan), service vulnerability search
(Vulners/NVD/Exploit-DB) and one link per CVE found by NSE (NVD), plus a MAC
vendor lookup (maclookup.app). Opening a link needs a browser (`xdg-open` on
Linux); the URL is also written to the Log.

## Architecture

```
include/vnm/        public API headers
src/core/           GUI-independent core
  model.cpp         data model + risk assessment
  net.cpp           interface detection (getifaddrs / GetAdaptersAddresses)
  scan.cpp          nmap runner (POSIX fork/exec or Windows CreateProcess)
  parse.cpp         dependency-free Nmap XML parser
  layout.cpp        /24 subnet clustering + 2D grid layout
  diff.cpp          scan comparison (added/removed/changed)
  storage.cpp       SQLite backend (scans/hosts/ports) + history
  platform.cpp      portable helpers (process id)
  passive.cpp       passive discovery (libpcap) + ARP/DHCP decoders
  export.cpp        SVG / PNG / JSON export
src/cli/main.cpp    CLI bootstrap
src/ui/             native 2D GUI (GLFW + OpenGL3 + Dear ImGui docking)
  main.cpp          app, docking layout, Inspector/Data/Log panels
  topology_view.cpp 2D canvas (pan/zoom, selection, minimap)
tests/              unit tests (CTest)
third_party/stb/    bundled stb_image_write + stb_easy_font
```

`vnm_core` (static library) has no GUI dependencies, so it is testable in
isolation and can be reused by both the CLI and the future GUI.

## Roadmap

- [x] Data model, risk assessment, Nmap XML parser, CLI runner
- [x] Interface auto-detection and subnet clustering
- [x] SQLite backend (`~/.config/vnm/storage.db`) and scan diffing
- [x] 2D GUI (Dear ImGui): canvas, minimap, inspector, docking
- [x] Windows support (MSVC) + GitHub Actions release builds
- [x] Passive discovery (ARP/DHCP via libpcap)
- [x] SVG/PNG/JSON export
- [ ] PDF export

## License

To be determined.
