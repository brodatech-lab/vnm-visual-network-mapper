[English](README.md) | [Polski](README.pl.md)

# VNM – Visual Network Mapper

Natywne narzędzie desktopowe dla inżynierów sieciowych, pentesterów i homelabów.
Płaski, czytelny podgląd 2D topologii sieci (węzły, podsieci `/24`, statusy
bezpieczeństwa) oparty na wynikach skanowania Nmapa.

> **Status:** `v0.4.0` – natywny rdzeń (silnik + CLI), backend SQLite z historią
> i diffingiem, natywne GUI 2D (Dear ImGui docking) oraz wsparcie **Windows +
> Linux**.

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
```

Opcje `scan`: `--os`, `--no-service`, `--no-save`, `--nmap <path>`, `-T<n>`,
`--arg <value>`.

Baza danych domyślnie: `~/.config/vnm/storage.db` (nadpisanie przez `VNM_DB`).

## GUI (mapa 2D)

Zbuduj z `-DVNM_BUILD_GUI=ON` i uruchom `vnm_gui`:

```sh
cmake -S . -B build/debug -DVNM_BUILD_GUI=ON
cmake --build build/debug -j
./build/debug/src/ui/vnm_gui --demo          # wbudowana przykładowa topologia
./build/debug/src/ui/vnm_gui scan.xml        # wczytaj plik Nmap XML
./build/debug/src/ui/vnm_gui --id 1          # wczytaj skan #1 z bazy
./build/debug/src/ui/vnm_gui --scan 192.168.0.1/24   # od razu uruchom skan
```

Funkcje: dokowane panele (Canvas / Inspector / Scan / Data / Log), pan & zoom,
dopasowanie widoku, ramki podsieci, kolory ryzyka, minimapa z prostokątem
widoku, klik-nie-inspect z tabelą portów oraz wyszukiwanie (`ip`, `host`,
`vendor` lub `port:22`). Mapa pokazuje tylko hosty, które odpowiedziały
(przełącznik **Only responding**); adresy przyjęte przez nmapa jako „up" bez
odpowiedzi są ukryte.

Panel **Scan** uruchamia `nmap` w tle dopiero po kliknięciu **Scan** (cel,
`-sV`, `-O`, timing; z przyciskiem **Cancel** oraz verbose, czytelnym logiem
natywnego outputu nmapa — inicjalizacja skanów, wykryte otwarte porty, raporty
hostów). Wyniki zastępują mapę po zakończeniu skanu.

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
src/cli/main.cpp    bootstrap CLI
src/ui/             natywne GUI 2D (GLFW + OpenGL3 + Dear ImGui docking)
  main.cpp          aplikacja, dokowanie, panele Inspector/Data/Log
  topology_view.cpp canvas 2D (pan/zoom, zaznaczanie, minimapa)
tests/              testy jednostkowe (CTest)
```

`vnm_core` (biblioteka statyczna) nie ma zależności GUI, dzięki czemu jest
testowalna w izolacji i może być użyta zarówno przez CLI, jak i przyszły GUI.

## Roadmap

- [x] Model danych, ocena ryzyka, parser XML Nmapa, runner CLI
- [x] Auto-detekcja interfejsów i klastrowanie podsieci
- [x] Backend SQLite (`~/.config/vnm/storage.db`) i diffing skanów
- [x] GUI 2D (Dear ImGui): canvas, minimapa, inspector, docking
- [x] Wsparcie Windows (MSVC) + buildy release przez GitHub Actions
- [ ] Pasywne wykrywanie (libpcap), eksport SVG/PNG/PDF

## Licencja

Do ustalenia.
