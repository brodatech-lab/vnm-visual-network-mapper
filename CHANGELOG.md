[English](CHANGELOG.md) | [Polski](CHANGELOG.pl.md)

# Changelog

All notable changes to the VNM project. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [Semantic Versioning](https://semver.org/).

## [0.6.1] - unreleased

### Added

- Canvas interaction: host blocks are **draggable** to any position (per-host
  offset); clicking a host opens a **persistent detail card** drawn on the
  canvas itself, connected to the node by a line. Multiple cards can stay open
  at once, cards are draggable too, and each closes via its **×** (top-right).
  The Inspector mirrors the last focused host.
- Detail cards live in **world space**, so they scale and move together with the
  map when zooming/panning (same as host nodes).

## [0.6.0] - 2026-10-09

Topology export (SVG / PNG / JSON).

### Added

- `vnm/export.hpp` + `src/core/export.cpp`: `export_scan()` renders the current
  topology layout to **SVG** (vector), **PNG** (raster) or **JSON** (full scan
  data). PNG uses the bundled `stb_image_write` + `stb_easy_font`; SVG/JSON are
  dependency-free.
- CLI `vnm export <file.xml> [--format svg|png|json] [--out <path>]` (also
  `--id N [--db <path>]` to export a stored scan).
- `import_scan_json()` plus **File → Load JSON…** in the GUI and a Data-panel
  loader, so an exported map can be loaded back onto the canvas
  (`vnm_gui map.json` also works). **Browse…** opens a built-in file browser
  (folder listing, no external tools/processes).
- **About** dialog: program name, current version, author `brodatech` and
  clickable links (`brodatech.pl`, `github.com/brodatech-lab`).
- Application icon (magnifier over a network): window icon on Linux/Windows
  plus a Windows `.exe` icon resource (`assets/vnm.ico`); `assets/vnm.png` and
  `packaging/vnm.desktop` for Linux desktop integration.
- GUI **Data** panel: export base path + **SVG / PNG / JSON** buttons.
- `test_export` (SVG/JSON content, PNG signature, JSON round-trip);
  8/8 CTest tests.
- Vendored `third_party/stb` single-header libraries.

### Changed

- Removed the built-in demo scan; the app now starts with an empty canvas.
- Removed the **View** menu (fit-to-view is on the canvas toolbar).

### Notes

- SVG/PNG show the map (responding hosts only); JSON contains the full scan
  (all hosts and ports).

## [0.5.2] - 2026-10-09

### Added

- Windows passive discovery: CMake now fetches the **Npcap SDK** at configure
  time (build-time only) and links `wpcap`/`Packet`; `VNM_NPCAP_SDK_DIR` can
  point at an existing SDK. Cross builds stay disabled.
- `PassiveScanner::devices()` (via `pcap_findalldevs`): the GUI and CLI list
  real capture devices, so Windows `\Device\NPF_{GUID}` names work (and the
  panel shows the friendly description).

### Notes

- On Windows, install Npcap and run as Administrator (unless Npcap was installed
  with the non-admin option). On Linux, `CAP_NET_RAW` is required.

## [0.5.1] - 2026-10-09

### Fixed

- GUI Passive panel: pressing **Stop** caused a crash (use-after-free) because
  the frame kept using `app.passive` after it was reset to null; the status
  line now checks the scanner pointer before dereferencing it.

## [0.5.0] - 2026-10-09

Passive discovery (ARP + DHCP).

### Added

- `vnm/passive.hpp` + `src/core/passive.cpp`: dependency-free ARP and DHCP
  decoders (hostname option 12, vendor class option 60, requested IP option 50)
  and a `PassiveScanner` built on libpcap (background capture thread, BPF
  filter `arp or (udp and (port 67 or port 68))`).
- CLI `vnm sniff [--iface <dev>] [--seconds N]` — live passive observations,
  de-duplicated by MAC/IP.
- GUI **Passive** panel: interface picker, Start/Stop, live table (IP/MAC/
  hostname/vendor) and **Merge to map** that folds observations into the
  current topology.
- CMake option `VNM_ENABLE_PCAP` (AUTO): ON when libpcap is found,
  automatically OFF when cross-compiling or when no pcap/Npcap is present.
- `test_passive`: ARP/DHCP decoders exercised on synthetic frames (no root).

### Notes

- Linux passive capture needs `CAP_NET_RAW` (root or
  `setcap cap_net_raw,cap_net_admin=eip ./vnm_gui`).
- Windows build keeps passive disabled (stub) until the Npcap SDK is provided.

## [0.4.2] - 2026-10-09

### Added

- Host responsiveness: the nmap `<status reason>` is now parsed and hosts that
  were assumed up without a real reply (e.g. `user-set`, `unknown-response`)
  are kept off the 2D map; any open port always counts as responsive.
- Canvas toggle **Only responding** (default on) and
  `LayoutConfig::only_responsive`.

### Fixed

- The topology map no longer fills up with every address of a scanned range
  when nmap reports hosts as up without an actual response.

## [0.4.1] - 2026-10-09

### Fixed

- Windows CI: configure with the Ninja generator inside the MSVC developer
  environment (the hosted `windows-latest` image no longer exposes the
  "Visual Studio 17 2022" generator by name). Windows builds now also run the
  test suite.
- `test_net`: the `/proc/net/route` parsing checks are Linux-only, so the
  Windows test run passes (Windows reads real routes via the IP Helper API).

## [0.4.0] - 2026-10-09

Cross-platform: Windows support (MSVC) alongside Linux.

### Added

- Windows process runner (`CreateProcess` + `CreatePipe`, non-blocking
  `PeekNamedPipe`/`ReadFile`, `TerminateProcess` for cancel, exit codes) behind
  `#ifdef _WIN32`; the `LineCallback` interface is unchanged.
- Windows interface/route detection via `GetAdaptersAddresses` and
  `GetIpForwardTable2` (IP Helper API), including MAC and friendly names.
- Windows default database path `%APPDATA%\vnm\storage.db`.
- `vnm::process_id()` portable helper (`getpid`/`_getpid`).
- Cross-platform CMake: SQLite amalgamation fallback via FetchContent, GLFW
  fetched on Windows, links `ws2_32`/`iphlpapi`, MSVC `/utf-8`, and a
  `windows-msvc` CMake preset.
- GitHub Actions release workflow building Linux (GCC + `ctest`) and Windows
  (MSVC) binaries and attaching them to the GitHub Release.

### Changed

- Project/CLI version bumped to `0.4.0`.
- On Windows, run as Administrator for `-sS`/`-O`/ARP scans; requires Nmap for
  Windows (which bundles Npcap).

## [0.3.1] - 2026-10-09

### Added

- GUI **Scan** panel: run `nmap` on demand from the UI (target, `-sV`, `-O`,
  timing) on a background thread, with a **Cancel** button and a verbose,
  human-readable log (nmap's native output: initiating scans, discovered open
  ports, per-host reports) instead of raw XML; results replace the map when the
  scan finishes. XML is written to a temp file while normal output is streamed
  live (`-v --stats-every 5s`).
- GUI arguments `--scan <target>` and `--no-service` to start a scan at launch.

## [0.3.0] - 2026-10-09

Native 2D GUI (Dear ImGui docking).

### Added

- `vnm_gui` native 2D viewer built on GLFW + OpenGL3 + Dear ImGui (docking
  branch, fetched automatically via CMake FetchContent).
- Docked layout: Canvas (centre), Inspector and Data (right), Log (bottom).
- 2D topology canvas: drag to pan, wheel to zoom about the cursor, fit-to-view,
  subnet `/24` frames, risk colouring, gateway edges, click-to-select.
- Minimap with the current viewport rectangle.
- Inspector panel: host details (IP, MAC, vendor, OS/confidence, status, risk)
  and a ports table.
- Data panel: load from an Nmap XML file, from SQLite (path + scan id), or a
  built-in demo scan.
- Search/filter box supporting free text and `port:<n>` queries.
- CLI arguments: `vnm_gui [file.xml] [--id N] [--db PATH] [--demo]`.
- CMake option `VNM_BUILD_GUI` (default OFF).

### Notes

- The GUI requires a display (X11/Wayland) and OpenGL; it is not covered by
  the CTest suite.

## [0.2.0] - 2026-10-09

SQLite backend and scan diffing (time travel).

### Added

- SQLite backend (`vnm::Storage`): `scans` / `hosts` / `ports` schema with
  foreign keys and cascade deletes, indexes, transactional scan saving.
- Database path `~/.config/vnm/storage.db` (XDG) with `VNM_DB` override and
  automatic directory creation.
- API: `open`, `save_scan`, `list_scans` (history), `load_scan`, `delete_scan`,
  `diff`.
- `vnm/diff.hpp` module: `diff_scans` compares scans by host address and
  classifies `added` / `removed` / `changed` hosts, including added, removed
  and modified ports plus status changes.
- CLI: `vnm history`, `vnm show <id>`, `vnm diff <before> <after>`;
  `vnm scan` stores to the database by default (`--no-save` disables it),
  `vnm parse <file> --save`.
- Tests: `test_diff` (comparison logic) and `test_storage` (full database
  round-trip). 6/6 CTest tests passing.
- CMake: `find_package(SQLite3)` and `SQLite::SQLite3` linking.

### Changed

- CLI version bumped to `0.2.0`.

## [0.1.0] - 2026-10-09

First release: native application core and CLI bootstrap.

### Added

- Data model: `Host`, `Port`, `Scan`, `Interface`, `Route`, `TopologyLayout`.
- Host risk assessment (`Safe` / `Warning` / `Critical` / `Offline`) with a
  dangerous-service heuristic (telnet, ftp, rdp, vnc, smb, …).
- Network interface auto-detection (`getifaddrs` + `/sys/class/net` metadata)
  and routing table / default gateway from `/proc/net/route`.
- Nmap runner (`NmapRunner`): POSIX `fork`/`exec` + pipe, live XML line
  streaming, scan cancellation, execution error handling.
- Dependency-free Nmap XML parser (`NmapXmlParser`) with entity decoding and
  `host`/`ports`/`address`/`hostnames`/`os`/`runstats` support; skips
  `<hosthint>` duplicates.
- 2D topology engine: groups hosts into `/24` subnet clusters and produces a
  grid layout ready to be drawn on a canvas.
- `Storage` persistence interface (`~/.config/vnm/storage.db`); SQLite backend
  left as a stub.
- `vnm` CLI: `interfaces`, `parse`, `layout`, `scan`, `version`, `help`.
- CMake project (C++20) with a `vnm_core` library, CLI/tests targets,
  `CMakePresets.json` and the `VNM_WERROR` option.
- Unit tests (CTest): model, parser, layout, net – 4/4 passing.
- `scripts/setup-dev.sh`: dependency installation, optional scoped passwordless
  sudo, `setcap` for nmap.

### Notes

- The 2D GUI layer (Dear ImGui) is a separate milestone; the target is not
  active yet.
- A full `-sV` scan over a large port range can be slow in environments with
  filtered ports; default `--host-timeout`/`--max-retries` are planned.
