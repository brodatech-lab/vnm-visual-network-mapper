[English](CHANGELOG.md) | [Polski](CHANGELOG.pl.md)

# Changelog

All notable changes to the VNM project. Format based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [Semantic Versioning](https://semver.org/).

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
