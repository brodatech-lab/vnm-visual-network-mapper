[English](README.md) | [Polski](README.pl.md)

# VNM – Visual Network Mapper

Natywne narzędzie desktopowe dla inżynierów sieciowych, pentesterów i homelabów.
Płaski, czytelny podgląd 2D topologii sieci (węzły, podsieci `/24`, statusy
bezpieczeństwa) oparty na wynikach skanowania Nmapa.

> **Status:** `v0.6.0` – natywny rdzeń (silnik + CLI), historia + diffing na
> SQLite, natywne GUI 2D (Dear ImGui docking), wsparcie **Windows + Linux**,
> **pasywne wykrywanie** (ARP/DHCP) oraz **eksport SVG/PNG/JSON**.

## Dlaczego

- Brak Electrona / web-stacka: start w ułamku sekundy, niskie zużycie RAM.
- Automatyczne klastrowanie hostów w ramki podsieci `/24`.
- Kolorystyka ryzyka: 🟢 bezpieczny · 🟡 uwaga · 🔴 krytyczny · ⚪ offline.
- Jedna binarka na Linuksa i Windowsa, bez Node.js / Pythona / Dockera.

## Wymagania

- Kompilator C++20 (GCC 13+ / Clang 16+ na Linuksie; MSVC 2022 na Windows)
- CMake ≥ 3.20
- `nmap` w `PATH` (skanowanie)
- Linux: opcjonalnie `setcap` dla detekcji OS / skanów SYN
- Windows: **Nmap for Windows** (zawiera Npcap); uruchamiaj jako Administrator
  dla `-sS`/`-O`/ARP, w przeciwnym razie użyj connect scan (`-sT`)
- GUI: GLFW 3.3+ oraz OpenGL (Dear ImGui pobierany przez CMake FetchContent przy
  pierwszej konfiguracji GUI – wymaga jednorazowo sieci)
- Pasywne wykrywanie (Linux): `libpcap` (auto-detekcja). Nadaj jednorazowo
  uprawnienia przez `sudo ./scripts/setcap.sh`, by przechwytywanie działało bez
  uruchamiania jako root.
- Pasywne wykrywanie (Windows): zainstaluj sterownik **Npcap** (SDK Npcap jest
  pobierany automatycznie na etapie build); uruchamiaj jako Administrator

## Szybki start (Linux)

Instalacja zależności i konfiguracja środowiska (raz, wymaga sudo):

```sh
sudo ./scripts/setup-dev.sh
```

Budowa i testy:

```sh
cmake -S . -B build/debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build/debug -j
ctest --test-dir build/debug --output-on-failure
```

## Budowa na Windows

Z Visual Studio 2022 (MSVC) i CMake:

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DVNM_BUILD_GUI=ON
cmake --build build --config Release --parallel
# binarki: build\Release\vnm.exe oraz build\src\ui\Release\vnm_gui.exe
```

(albo preset `windows-msvc`). Gotowe `.exe`/binarki Linuksa produkuje workflow
GitHub Actions przy tagach wersji.

## Użycie (CLI)

```sh
./build/debug/vnm interfaces              # interfejsy lokalne + brama domyślna
./build/debug/vnm scan 192.168.0.0/24     # uruchom nmap, wypisz i zapisz hosty
./build/debug/vnm parse scan.xml --save   # parsuj wynik Nmap XML i zapisz
./build/debug/vnm layout scan.xml         # przelicz klastry podsieci 2D
./build/debug/vnm history                 # lista zapisanych skanów
./build/debug/vnm show 1                  # wypisz zapisany skan
./build/debug/vnm diff 1 2                # porównaj dwa skany (time travel)
./build/debug/vnm sniff --seconds 10      # pasywne wykrywanie ARP/DHCP
./build/debug/vnm export scan.xml --format svg --out map.svg   # eksport mapy
```

Opcje `scan`: `--os`, `--no-service`, `--scripts` (`-sC`), `--vuln`
(`--script default,vuln`), `--no-save`, `--nmap <path>`, `-T<n>`, `--arg <value>`.

Baza danych domyślnie: `~/.config/vnm/storage.db` (nadpisanie przez `VNM_DB`).

## GUI (mapa 2D)

Zbuduj z `-DVNM_BUILD_GUI=ON` i uruchom `vnm_gui`:

```sh
cmake -S . -B build/debug -DVNM_BUILD_GUI=ON
cmake --build build/debug -j
./build/debug/src/ui/vnm_gui                 # pusty canvas
./build/debug/src/ui/vnm_gui scan.xml        # wczytaj plik Nmap XML
./build/debug/src/ui/vnm_gui map.json        # wczytaj zapisany JSON mapy
./build/debug/src/ui/vnm_gui --id 1          # wczytaj skan #1 z bazy
./build/debug/src/ui/vnm_gui --scan 192.168.0.1/24   # od razu uruchom skan
```

Menu **File → Load JSON…** (z natywnym wyborem pliku) wczytuje wcześniej
wyeksportowaną mapę z powrotem na canvas. **About** pokazuje wersję i linki.

Funkcje: dokowane panele (Canvas / Inspector / Scan / Data / Log), pan & zoom,
dopasowanie widoku, ramki podsieci, kolory ryzyka, minimapa z prostokątem
widoku, klik-nie-inspect z tabelą portów oraz wyszukiwanie (`ip`, `host`,
`vendor` lub `port:22`). Mapa pokazuje tylko hosty, które odpowiedziały
(przełącznik **Only responding**); adresy przyjęte przez nmapa jako „up" bez
odpowiedzi są ukryte.

Panel **Scan** uruchamia `nmap` w tle dopiero po kliknięciu **Scan** (cel,
`-sV`, `-O`, timing; z przyciskiem **Cancel** oraz verbose, czytelnym logiem
natywnego outputu nmapa — inicjalizacja skanów, wykryte otwarte porty, raporty
hostów). Wyniki zastępują mapę po zakończeniu skanu, a mapa **buduje się na
żywo** w trakcie skanu (nowe hosty/porty pojawiają się w miarę wykrywania;
kamera i pozycje nod są zachowywane).

Panel **Passive** nasłuchuje ruchu ARP/DHCP (wymaga `CAP_NET_RAW` na Linuksie)
i wypisuje zaobserwowane hosty; **Merge to map** włącza je do topologii.

Każda karta szczegółów hosta (oraz Inspector) pokazuje klikalne **linki
referencyjne** dla otwartych portów: info o porcie (SpeedGuide/IANA/Shodan),
wyszukiwarka podatności usługi (Vulners/NVD/Exploit-DB) oraz link do każdego CVE
wykrytego przez NSE (NVD), a także sprawdzenie vendora po MAC (maclookup.app).
Linki otwierają się w prawdziwej przeglądarce (firefox/chromium wykrywane z
`PATH`, nadpisanie przez `VNM_BROWSER` lub pole **Browser**); dokładna komenda
trafia do Logu.

## Architektura

```
include/vnm/        publiczne nagłówki API
src/core/           rdzeń niezależny od GUI
  model.cpp         model danych + ocena ryzyka
  net.cpp           detekcja interfejsów (getifaddrs / GetAdaptersAddresses)
  scan.cpp          runner nmap (POSIX fork/exec lub Windows CreateProcess)
  parse.cpp         bezzależnościowy parser XML Nmapa
  layout.cpp        klastrowanie podsieci /24 + układ siatki 2D
  diff.cpp          porównywanie skanów (added/removed/changed)
  storage.cpp       backend SQLite (scans/hosts/ports) + historia
  platform.cpp      przenośne helpery (process id)
  passive.cpp       pasywne wykrywanie (libpcap) + dekodery ARP/DHCP
  export.cpp        eksport SVG / PNG / JSON
src/cli/main.cpp    bootstrap CLI
src/ui/             natywne GUI 2D (GLFW + OpenGL3 + Dear ImGui docking)
  main.cpp          aplikacja, dokowanie, panele Inspector/Data/Log
  topology_view.cpp canvas 2D (pan/zoom, zaznaczanie, minimapa)
tests/              testy jednostkowe (CTest)
third_party/stb/    dołączone stb_image_write + stb_easy_font
```

`vnm_core` (biblioteka statyczna) nie ma zależności GUI, dzięki czemu jest
testowalna w izolacji i może być użyta zarówno przez CLI, jak i przyszły GUI.

## Roadmap

- [x] Model danych, ocena ryzyka, parser XML Nmapa, runner CLI
- [x] Auto-detekcja interfejsów i klastrowanie podsieci
- [x] Backend SQLite (`~/.config/vnm/storage.db`) i diffing skanów
- [x] GUI 2D (Dear ImGui): canvas, minimapa, inspector, docking
- [x] Wsparcie Windows (MSVC) + buildy release przez GitHub Actions
- [x] Pasywne wykrywanie (ARP/DHCP przez libpcap)
- [x] Eksport SVG/PNG/JSON
- [ ] Eksport PDF

## Licencja

Do ustalenia.
