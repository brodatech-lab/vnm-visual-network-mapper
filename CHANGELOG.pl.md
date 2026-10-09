[English](CHANGELOG.md) | [Polski](CHANGELOG.pl.md)

# Changelog

Wszystkie istotne zmiany w projekcie VNM. Format oparty o
[Keep a Changelog](https://keepachangelog.com/pl/1.0.0/),
wersjonowanie zgodne z [Semantic Versioning](https://semver.org/lang/pl/).

## [0.6.1] - unreleased

### Dodane

- Interakcja na canvasie: bloki hostów są **przeciągalne** w dowolne miejsce
  (offset per host); kliknięcie hosta otwiera **trwałą kartę szczegółów**
  rysowaną na canvasie, połączoną z węzłem linią. Wiele kart może być otwartych
  naraz, karty też można przeciągać, a każda zamyka się przez **×** (prawy górny
  róg). Inspector odzwierciedla ostatnio wybrany host.
- Karty szczegółów są w **world space**, więc skalują się i przesuwają razem z
  mapą przy zoomie/panie (tak samo jak bloki hostów).
- Ramka podsieci (z CIDR skanu) jest liczona z aktualnych pozycji nod, więc
  powiększa się i przesuwa tak, by obejmować swoje (przestawiane) hosty.
- Domyślny układ mapy jest teraz **radialny wokół bramy**: host `.1` siedzi w
  środku ramki podsieci, a pozostałe hosty są rozłożone na okręgu wokół niego
  (krawędzie nadal rozchodzą się od środka).
- Kliknięcie karty szczegółów wysuwa ją na **wierzch** (karty testowane od
  wierzchu, kliknięta karta trafia na koniec kolejności rysowania).
- Parsowanie NSE: wyniki `<script>` i `<hostscript>` trafiają do modelu
  (`Script`, `cves`), a identyfikatory `CVE-YYYY-NNNN` są wyciągane dla portów
  i hostów.
- **Linki referencyjne** na kartach szczegółów (canvas) i w Inspectorze: info o
  porcie (SpeedGuide / IANA / Shodan), wyszukiwarka podatności usługi (Vulners /
  NVD / Exploit-DB) oraz link do każdego CVE (NVD). Chipy tekstowe otwierają się
  w przeglądarce systemowej.
- Opcje skanowania `-sC` (domyślne skrypty) i `--script default,vuln`
  (checkboxy w GUI; CLI `--scripts` / `--vuln`), dzięki czemu podatności są
  wykrywane.
- Eksport/import JSON zachowuje teraz skrypty NSE i CVEs.
- Nowy moduł `vnm/links.hpp` i `test_links` (9/9 testów CTest).

## [0.6.0] - 2026-10-09

Eksport topologii (SVG / PNG / JSON).

### Dodane

- `vnm/export.hpp` + `src/core/export.cpp`: `export_scan()` renderuje bieżący
  układ topologii do **SVG** (wektor), **PNG** (raster) lub **JSON** (pełne dane
  skanu). PNG korzysta z dołączonych `stb_image_write` + `stb_easy_font`;
  SVG/JSON są bezzależnościowe.
- CLI `vnm export <file.xml> [--format svg|png|json] [--out <path>]` (także
  `--id N [--db <path>]` dla skanu z bazy).
- `import_scan_json()` oraz **File → Load JSON…** w GUI i loader w panelu Data,
  dzięki czemu wyeksportowaną mapę można wczytać z powrotem na canvas
  (`vnm_gui map.json` też działa). **Browse…** otwiera wbudowaną przeglądarkę
  plików (lista katalogów, bez narzędzi/procesów zewnętrznych).
- Okno **About**: nazwa programu, aktualna wersja, autor `brodatech` oraz
  klikalne linki (`brodatech.pl`, `github.com/brodatech-lab`).
- Ikona aplikacji (lupka nad siecią): ikona okna na Linux/Windows oraz zasób
  ikony Windows `.exe` (`assets/vnm.ico`); `assets/vnm.png` i
  `packaging/vnm.desktop` do integracji z pulpitem Linuksa.
- GUI panel **Data**: ścieżka bazowa eksportu + przyciski **SVG / PNG / JSON**.
- `test_export` (treść SVG/JSON, sygnatura PNG, round-trip JSON); 8/8 testów CTest.
- Dołączone biblioteki nagłówkowe `third_party/stb`.

### Zmienione

- Usunięto wbudowany skan demo; aplikacja startuje z pustym canvasem.
- Usunięto menu **View** (dopasowanie widoku jest na pasku canvasu).

### Uwagi

- SVG/PNG pokazują mapę (tylko odpowiadające hosty); JSON zawiera pełny skan
  (wszystkie hosty i porty).

## [0.5.2] - 2026-10-09

### Dodane

- Pasywne wykrywanie na Windows: CMake pobiera teraz **Npcap SDK** na etapie
  konfiguracji (tylko build) i linkuje `wpcap`/`Packet`; `VNM_NPCAP_SDK_DIR`
  może wskazać istniejące SDK. Cross-compile pozostaje wyłączony.
- `PassiveScanner::devices()` (przez `pcap_findalldevs`): GUI i CLI pokazują
  prawdziwe urządzenia przechwytujące, więc nazwy Windows `\Device\NPF_{GUID}`
  działają (a panel pokazuje czytelny opis).

### Uwagi

- Na Windows zainstaluj Npcap i uruchamiaj jako Administrator (chyba że Npcap
  zainstalowano z opcją non-admin). Na Linuksie wymagane `CAP_NET_RAW`.

## [0.5.1] - 2026-10-09

### Naprawione

- Panel GUI Passive: kliknięcie **Stop** powodowało crash (use-after-free),
  ponieważ dana klatka nadal używała `app.passive` po zresetowaniu go do null;
  linia statusu sprawdza teraz wskaźnik scannera przed użyciem.

## [0.5.0] - 2026-10-09

Pasywne wykrywanie (ARP + DHCP).

### Dodane

- `vnm/passive.hpp` + `src/core/passive.cpp`: bezzależnościowe dekodery ARP i
  DHCP (hostname opcja 12, vendor class opcja 60, żądany IP opcja 50) oraz
  `PassiveScanner` na libpcap (wątek capture w tle, filtr BPF
  `arp or (udp and (port 67 or port 68))`).
- CLI `vnm sniff [--iface <dev>] [--seconds N]` — obserwacje na żywo,
  deduplikowane po MAC/IP.
- GUI: panel **Passive** — wybór interfejsu, Start/Stop, tabela na żywo
  (IP/MAC/hostname/vendor) oraz **Merge to map** włączający obserwacje do
  bieżącej topologii.
- Opcja CMake `VNM_ENABLE_PCAP` (AUTO): ON gdy libpcap znaleziony, automatycznie
  OFF przy cross-compile lub gdy brak pcap/Npcap.
- `test_passive`: dekodery ARP/DHCP na syntetycznych ramkach (bez roota).

### Uwagi

- Pasywne przechwytywanie na Linuksie wymaga `CAP_NET_RAW` (root lub
  `setcap cap_net_raw,cap_net_admin=eip ./vnm_gui`).
- Build Windows ma passive wyłączone (stub) do czasu dodania Npcap SDK.

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
