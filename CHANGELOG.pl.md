[English](CHANGELOG.md) | [Polski](CHANGELOG.pl.md)

# Changelog

Wszystkie istotne zmiany w projekcie VNM. Format oparty o
[Keep a Changelog](https://keepachangelog.com/pl/1.0.0/),
wersjonowanie zgodne z [Semantic Versioning](https://semver.org/lang/pl/).

## [0.4.2] - 2026-10-09

### Dodane

- Rozpoznawanie odpowiedzi hosta: parsowany jest `<status reason>` nmapa, a
  hosty przyjęte jako „up" bez realnej odpowiedzi (np. `user-set`,
  `unknown-response`) nie trafiają na mapę 2D; otwarty port zawsze liczy się
  jako odpowiedź.
- Przełącznik w canvasie **Only responding** (domyślnie włączony) oraz
  `LayoutConfig::only_responsive`.

### Naprawione

- Mapa topologii nie wypełnia się już wszystkimi adresami zakresu, gdy nmap
  oznacza hosty jako „up" bez faktycznej odpowiedzi.

## [0.4.1] - 2026-10-09

### Naprawione

- CI Windows: konfiguracja generatorem Ninja w środowisku deweloperskim MSVC
  (hostowany obraz `windows-latest` nie udostępnia już generatora o nazwie
  „Visual Studio 17 2022"). Buildy Windows uruchamiają teraz także testy.
- `test_net`: sprawdzenia parsera `/proc/net/route` są tylko dla Linuksa, więc
  testy na Windows przechodzą (Windows czyta realne trasy przez IP Helper API).

## [0.4.0] - 2026-10-09

Wieloplatformowość: wsparcie Windows (MSVC) obok Linuksa.

### Dodane

- Runner procesów dla Windows (`CreateProcess` + `CreatePipe`, nieblokujący
  odczyt `PeekNamedPipe`/`ReadFile`, `TerminateProcess` dla anulowania, kody
  wyjścia) pod `#ifdef _WIN32`; interfejs `LineCallback` bez zmian.
- Detekcja interfejsów i tras na Windows przez `GetAdaptersAddresses` oraz
  `GetIpForwardTable2` (IP Helper API), z MAC i nazwami przyjaznymi.
- Domyślna ścieżka bazy na Windows: `%APPDATA%\vnm\storage.db`.
- Przenośny helper `vnm::process_id()` (`getpid`/`_getpid`).
- Cross-platform CMake: fallback amalgamacji SQLite przez FetchContent, GLFW
  pobierany na Windows, link `ws2_32`/`iphlpapi`, MSVC `/utf-8` oraz preset
  `windows-msvc`.
- Workflow GitHub Actions budujący binarki Linux (GCC + `ctest`) i Windows
  (MSVC) i dołączający je do GitHub Release.

### Zmienione

- Wersja projektu/CLI podniesiona do `0.4.0`.
- Na Windows uruchamiaj jako Administrator dla `-sS`/`-O`/ARP; wymagany Nmap for
  Windows (zawiera Npcap).

## [0.3.1] - 2026-10-09

### Dodane

- Panel GUI **Scan**: uruchamianie `nmap` na żądanie z poziomu UI (cel, `-sV`,
  `-O`, timing) w wątku tła, z przyciskiem **Cancel** oraz verbose, czytelnym
  logiem (natywny output nmapa: inicjalizacja skanów, wykryte otwarte porty,
  raporty hostów) zamiast surowego XML; po zakończeniu skanu wyniki zastępują
  mapę. XML trafia do pliku tymczasowego, a normalny output leci na żywo
  (`-v --stats-every 5s`).
- Argumenty GUI `--scan <target>` i `--no-service` do startu skanu przy starcie.

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
