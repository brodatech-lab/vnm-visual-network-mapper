[English](CHANGELOG.md) | [Polski](CHANGELOG.pl.md)

# Changelog

Wszystkie istotne zmiany w projekcie VNM. Format oparty o
[Keep a Changelog](https://keepachangelog.com/pl/1.0.0/),
wersjonowanie zgodne z [Semantic Versioning](https://semver.org/lang/pl/).

## [0.3.0] - 2026-10-09

Natywne GUI 2D (Dear ImGui docking).

### Dodane

- `vnm_gui` – natywny podgląd 2D oparty o GLFW + OpenGL3 + Dear ImGui (branch
  docking, pobierany automatycznie przez CMake FetchContent).
- Układ dokowany: Canvas (środek), Inspector i Data (prawa), Log (dół).
- Canvas topologii 2D: przeciąganie = pan, kółko = zoom pod kursorem,
  dopasowanie widoku, ramki podsieci `/24`, kolory ryzyka, krawędzie do bramy,
  klik = zaznaczenie.
- Minimapa z prostokątem aktualnego widoku.
- Panel Inspector: szczegóły hosta (IP, MAC, vendor, OS/pewność, status,
  ryzyko) oraz tabela portów.
- Panel Data: wczytywanie z pliku Nmap XML, z SQLite (ścieżka + id skanu) lub
  wbudowany skan demo.
- Pole wyszukiwania/filtrowania z obsługą tekstu i zapytań `port:<n>`.
- Argumenty CLI: `vnm_gui [file.xml] [--id N] [--db PATH] [--demo]`.
- Opcja CMake `VNM_BUILD_GUI` (domyślnie OFF).

### Uwagi

- GUI wymaga displaya (X11/Wayland) oraz OpenGL; nie jest objęte testami CTest.

## [0.2.0] - 2026-10-09

Backend SQLite i diffing skanów (time travel).

### Dodane

- Backend SQLite (`vnm::Storage`): schemat `scans` / `hosts` / `ports` ze
  kluczami obcymi i kaskadowym usuwaniem, indeksy, transakcyjny zapis skanu.
- Ścieżka bazy `~/.config/vnm/storage.db` (XDG) z nadpisaniem przez `VNM_DB`
  i automatycznym tworzeniem katalogów.
- API: `open`, `save_scan`, `list_scans` (historia), `load_scan`, `delete_scan`,
  `diff`.
- Moduł `vnm/diff.hpp`: `diff_scans` porównujący skany po adresie hosta,
  klasyfikacja `added` / `removed` / `changed` z portami dodanymi, usuniętymi
  i zmodyfikowanymi oraz zmianą statusu.
- CLI: `vnm history`, `vnm show <id>`, `vnm diff <before> <after>`;
  `vnm scan` zapisuje do bazy domyślnie (`--no-save` wyłącza),
  `vnm parse <file> --save`.
- Testy: `test_diff` (logika porównania) i `test_storage` (pełny round-trip
  bazy). Razem 6/6 testów CTest.
- CMake: `find_package(SQLite3)` i linkowanie `SQLite::SQLite3`.

### Zmienione

- Wersja CLI podniesiona do `0.2.0`.

## [0.1.0] - 2026-10-09

Pierwsza wersja: natywny rdzeń aplikacji i bootstrap CLI.

### Dodane

- Model danych: `Host`, `Port`, `Scan`, `Interface`, `Route`, `TopologyLayout`.
- Ocena ryzyka hosta (`Safe` / `Warning` / `Critical` / `Offline`) z heurystyką
  usług niebezpiecznych (telnet, ftp, rdp, vnc, smb, …).
- Auto-detekcja interfejsów sieciowych (`getifaddrs` + metadane
  `/sys/class/net`) oraz tabeli routingu i bramy domyślnej z `/proc/net/route`.
- Runner Nmapa (`NmapRunner`): POSIX `fork`/`exec` + pipe, strumieniowanie
  linii XML na żywo, anulowanie skanu, obsługa błędów wykonania.
- Bezzależnościowy parser XML Nmapa (`NmapXmlParser`) z dekodowaniem encji,
  obsługą `host`/`ports`/`address`/`hostnames`/`os`/`runstats`; pomija
  `<hosthint>` (duplikaty).
- Silnik topologii 2D: grupowanie hostów w klastry podsieci `/24` i układ
  siatki gotowy do rysowania na canvasie.
- Interfejs trwałości `Storage` (ścieżka `~/.config/vnm/storage.db`); backend
  SQLite pozostawiony jako stub.
- CLI `vnm`: `interfaces`, `parse`, `layout`, `scan`, `version`, `help`.
- Projekt CMake (C++20) z biblioteką `vnm_core`, targetami CLI/tests,
  `CMakePresets.json` i opcją `VNM_WERROR`.
- Testy jednostkowe (CTest): model, parser, layout, net – 4/4 zielone.
- Skrypt `scripts/setup-dev.sh`: instalacja zależności, opcjonalny scoped
  passwordless sudo, `setcap` dla nmapa.

### Uwagi

- Warstwa GUI 2D (Dear ImGui) – osobny milestone, target jeszcze nieaktywny.
- Pełny skan `-sV` na dużym zakresie portów może być wolny w środowiskach
  z filtrowanymi portami; w planach domyślne `--host-timeout`/`--max-retries`.
