# VNM – Visual Network Mapper

Natywne narzędzie desktopowe dla inżynierów sieciowych, pentesterów i homelabów.
Płaski, czytelny podgląd 2D topologii sieci (węzły, podsieci `/24`, statusy
bezpieczeństwa) oparty na wynikach skanowania Nmapa.

> **Status:** `v0.1.0` – ukończony natywny rdzeń (silnik + CLI). Warstwa GUI 2D
> (Dear ImGui) jest w fazie planowania.

## Dlaczego

- Brak Electrona / web-stacka: start w ułamku sekundy, niskie zużycie RAM.
- Automatyczne klastrowanie hostów w ramki podsieci `/24`.
- Kolorystyka ryzyka: 🟢 bezpieczny · 🟡 uwaga · 🔴 krytyczny · ⚪ offline.
- Jedna binarka, bez Node.js / Pythona / Dockera.

## Wymagania

- Kompilator C++20 (GCC 13+ lub Clang 16+)
- CMake ≥ 3.20
- `nmap` w `PATH` (skanowanie)
- Opcjonalnie: `nmap` + `setcap` dla detekcji OS / skanów SYN

## Szybki start

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

## Użycie (CLI)

```sh
./build/debug/vnm interfaces              # interfejsy lokalne + brama domyślna
./build/debug/vnm scan 192.168.0.0/24     # uruchom nmap i wypisz hosty
./build/debug/vnm parse scan.xml          # parsuj istniejący wynik Nmap XML
./build/debug/vnm layout scan.xml         # przelicz klastry podsieci 2D
```

Opcje `scan`: `--os`, `--no-service`, `--nmap <path>`, `-T<n>`, `--arg <value>`.

## Architektura

```
include/vnm/        publiczne nagłówki API
src/core/           rdzeń niezależny od GUI
  model.cpp         model danych + ocena ryzyka
  net.cpp           auto-detekcja interfejsów (/sys/class/net, /proc/net/route)
  scan.cpp          runner nmap (POSIX fork/exec + pipe, XML na żywo)
  parse.cpp         bezzależnościowy parser XML Nmapa
  layout.cpp        klastrowanie podsieci /24 + układ siatki 2D
  storage.cpp       interfejs trwałości (backend SQLite – w planach)
src/cli/main.cpp    bootstrap CLI
src/ui/             docelowy target GUI 2D (Dear ImGui + GLFW)
tests/              testy jednostkowe (CTest)
```

`vnm_core` (biblioteka statyczna) nie ma zależności GUI, dzięki czemu jest
testowalna w izolacji i może być użyta zarówno przez CLI, jak i przyszły GUI.

## Roadmap

- [x] Model danych, ocena ryzyka, parser XML Nmapa, runner CLI
- [x] Auto-detekcja interfejsów i klastrowanie podsieci
- [ ] Backend SQLite (`~/.config/vnm/storage.db`) i diffing skanów
- [ ] GUI 2D (Dear ImGui): canvas, minimapa, inspector, docking
- [ ] Pasywne wykrywanie (libpcap), eksport SVG/PNG/PDF

## Licencja

Do ustalenia.
