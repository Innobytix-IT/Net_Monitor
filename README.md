# Net-Monitor v2.0 – OpenScan Projekt

> Modernes Netzwerk-Überwachungstool mit Live-Dashboard, Anomalie-Erkennung, Geo-IP, DNS-Auflösung und Port-Scan-Erkennung.

**(C) 2023–2026 Manuel Person**

---

## Inhaltsverzeichnis

1. [Was ist neu in v2.0?](#was-ist-neu)
2. [Unterschiede zur alten Version](#unterschiede)
3. [Voraussetzungen](#voraussetzungen)
4. [Installation & Erster Start](#installation)
5. [Konfiguration](#konfiguration)
6. [Dashboard-Übersicht](#dashboard)
7. [Features im Detail](#features)
8. [Häufige Fragen (FAQ)](#faq)

---

## Was ist neu in v2.0? <a name="was-neu"></a>

Version 2.0 ist eine komplette Neuentwicklung gegenüber v1.0 und bringt folgende Verbesserungen:

| # | Verbesserung | Beschreibung |
|---|-----|--------------|
| 1 | **Korrekte Täter-Erkennung beim Alarm** | Der „Falscher Verdächtiger"-Bug wurde behoben: Bei einem Traffic-Spike wird jetzt das Gerät des *aktuellen* Intervalls gemeldet, nicht der All-Time-Top-Talker. |
| 2 | **Counter-Reset pro Intervall** | `ip_counter`, `port_counter` und `proto_counter` werden jetzt nach jedem Messintervall zurückgesetzt – kein Memory Leak mehr, das Dashboard zeigt aktuelle statt kumulierte Daten. |
| 3 | **Report-Rotation implementiert** | Der Config-Parameter `report_rotate` war bisher wirkungslos. Alte Reports werden jetzt automatisch nach der eingestellten Anzahl an Tagen gelöscht. |
| 4 | **Intelligente Geo-IP-Farbgebung** | IPs aus bekannten Cloud/CDN-Ländern (z.B. US, NL, IE) werden nicht mehr pauschal rot markiert. Das reduziert „Alert Fatigue" erheblich. |
| 5 | **DNS-Timeout** | DNS-Auflösungen haben jetzt einen 0,5s-Timeout, damit das Live-Dashboard nicht einfriert. |
| 6 | **PEP 668 (Linux)** | Die automatische Paketinstallation nutzt jetzt `--break-system-packages` auf modernen Linux-Systemen (Ubuntu 23.04+, Debian 12+). |
| 7 | **Einheitliche Dateipfade** | Alle Dateien (Config, Logs, Reports, GeoIP-DB) liegen jetzt konsistent im Skript-Verzeichnis, unabhängig vom Arbeitsverzeichnis beim Start. |
| 8 | **Tippfehler behoben** | „OpenSacn" → „OpenScan" in allen Bannern. |

---

## Unterschiede zur alten Version (v1.0 → v2.0) <a name="unterschiede"></a>

Die ursprüngliche Version war ein einfaches Single-File-Skript (~100 Zeilen). Die neue Version ist eine komplette Neuentwicklung.

### Architektur

| Merkmal | v1.0 (alt) | v2.0 (neu) |
|---------|-----------|-----------|
| Code-Umfang | ~100 Zeilen | ~900 Zeilen |
| Struktur | Einzelne Funktion | Klassen, Dataclasses, Module |
| Threading | Keines (blockierend) | Producer-Consumer mit Queue |
| Konfiguration | Hardcodiert im Code | JSON-Datei (`net_monitor_config.json`) |
| Plattformen | Nur Windows | Windows, Linux, macOS |

### Features

| Feature | v1.0 | v2.0 |
|---------|------|------|
| Paket-Erfassung | ✅ (nur IPv4) | ✅ IPv4 + IPv6 |
| Live-Dashboard | ❌ Nur Konsolen-`print` | ✅ Rich-Terminal-Dashboard |
| Sparkline-Verlauf | ❌ | ✅ Letzte 60 Messungen |
| Geo-IP (Ländererkennung) | ❌ | ✅ MaxMind GeoLite2 |
| DNS-Auflösung | ❌ | ✅ Mit Cache & Timeout |
| Port-Scan-Erkennung | ❌ | ✅ Konfigurierbar |
| Whitelist / Blacklist | ❌ | ✅ |
| Desktop-Benachrichtigung | ✅ (plyer) | ✅ (plyer + Fallback) |
| CSV-Export | ❌ Nur .txt | ✅ Strukturiertes CSV |
| JSON-Export | ❌ | ✅ Optional |
| Report-Rotation | ❌ | ✅ Automatisch nach N Tagen |
| First-Run-Assistent | ❌ | ✅ Installiert Abhängigkeiten |
| Interaktiver Setup-Wizard | ❌ | ✅ |
| Protokoll-Statistiken | ❌ | ✅ TCP/UDP/ICMP/Other |
| Top-Talker-Anzeige | ❌ | ✅ |
| Top-Ports-Anzeige | ❌ | ✅ |

### Behobene Schwächen der alten Version

- **Globale Variable `traffic_counter`** wurde ungeschützt aus mehreren Threads verändert → Race Condition. In v2.0 durch `threading.Lock()` abgesichert.
- **Kein Timeout für Report-Datei** – `report_file.close()` wurde nie erreicht (Endlosschleife ohne Break). In v2.0 korrekt mit `finally`-Block gelöst.
- **Schwellenwert-Eingabe nach der Baseline** – der Nutzer musste erst 60 Sekunden warten, bevor er den Schwellenwert eingeben konnte. In v2.0 ist alles konfigurierbar vor dem Start.
- **Nur Windows** – `perfmon`, `ctypes.windll` und `.exe`-Referenzen machten das Tool inkompatibel mit Linux/macOS.
- **Kein Mehrfach-Protokoll-Support** – ICMPv6, IPv6 und andere Protokolle wurden ignoriert.

---

## Voraussetzungen <a name="voraussetzungen"></a>

- **Python** 3.10 oder neuer
- **Windows**: Npcap ([npcap.com](https://npcap.com/#download)) oder Wireshark (enthält Npcap)
- **Linux/macOS**: Root-Rechte (`sudo`)

Die restlichen Python-Pakete installiert der First-Run-Assistent beim ersten Start automatisch:

```
scapy, rich, plyer, geoip2
```

### Optional: Geo-IP-Datenbank

Für die Länderanzeige wird die kostenlose **GeoLite2-City**-Datenbank von MaxMind benötigt:

1. Kostenloses Konto erstellen: [maxmind.com](https://www.maxmind.com/en/geolite2/signup)
2. `GeoLite2-City.mmdb` herunterladen
3. Die Datei in das gleiche Verzeichnis wie `net_monitor.py` kopieren

Ohne die Datei läuft das Tool normal – die Geo-IP-Spalte zeigt dann `–`.

---

## Installation & Erster Start <a name="installation"></a>

```bash
# 1. Skript herunterladen / in ein Verzeichnis legen
# 2. Starten (Linux/macOS mit sudo, Windows als Administrator)

# Linux / macOS:
sudo python3 net_monitor.py

# Windows (als Administrator):
python net_monitor.py
```

Beim **ersten Start** erscheint automatisch der Einrichtungsassistent:

- **Schritt 1**: Python-Pakete werden installiert
- **Schritt 2**: Npcap-Anleitung (nur Windows)
- **Schritt 3**: GeoLite2-Datenbank einrichten

Nach der Einrichtung startet das Tool direkt beim nächsten Start – der Assistent erscheint nicht mehr.

---

## Konfiguration <a name="konfiguration"></a>

Alle Einstellungen werden in `net_monitor_config.json` gespeichert und können direkt bearbeitet oder über den interaktiven Setup-Wizard (`Einstellungen anpassen? [j/N]`) geändert werden.

### Alle Parameter

| Parameter | Standard | Beschreibung |
|-----------|----------|--------------|
| `average_period` | `120` | Dauer der Baseline-Messung in Sekunden |
| `monitor_interval` | `30` | Dauer eines Messintervalls in Sekunden |
| `threshold` | `50` | Alarm-Schwellenwert in % über Baseline |
| `bpf_filter` | `"ip or ip6"` | BPF-Filter für Scapy (Paketfilter) |
| `interface` | `""` | Netzwerk-Interface (`""` = alle) |
| `notify_desktop` | `true` | Desktop-Benachrichtigung bei Alarm |
| `notify_log` | `true` | Log-Datei-Einträge aktivieren |
| `resolve_dns` | `true` | DNS-Auflösung im Dashboard |
| `geo_lookup` | `true` | Geo-IP-Ländererkennung |
| `detect_portscan` | `true` | Port-Scan-Erkennung aktiv |
| `portscan_limit` | `100` | Ports pro 10s für Portscan-Alarm |
| `whitelist` | `[...]` | IPs die keinen Alarm auslösen |
| `blacklist` | `[]` | IPs die sofort Alarm auslösen |
| `export_csv` | `true` | CSV-Report in `reports/` speichern |
| `export_json` | `false` | JSON-Report zusätzlich speichern |
| `report_rotate` | `7` | Reports nach N Tagen automatisch löschen |

---

## Dashboard-Übersicht <a name="dashboard"></a>

```
╔══════════════════════════════════════════════════════════════════════════╗
║  NET-MONITOR v2.0  │  Interface: alle  │  Filter: ip or ip6  │  Zeit   ║
╠══════════════╦═════════════════╦═══════════════════════════════════════╣
║ 📈 Verlauf   ║ pps: ▁▂▄▅▇█▇▅   ║ B/s: ▁▁▂▃▄▅▄▃                       ║
╠══════════════╬═════════════════╬═══════════════════════════════════════╣
║ 📊 Statistik ║ 🔌 Protokolle   ║ 🚨 Alarme                             ║
╠══════════════╩═════════════════╬═══════════════════════════════════════╣
║ 🔝 Top-Talker                  ║ 🔒 Top-Ports                          ║
╠════════════════════════════════╩═══════════════════════════════════════╣
║ 📦 Letzte Pakete  (🌍 Geo-IP aktiv)                                    ║
╚════════════════════════════════════════════════════════════════════════╝
```

### Geo-IP Farbcodes

| Farbe | Bedeutung |
|-------|-----------|
| 🟢 Grün | LAN-IP oder bekannte Cloud/CDN-Region (DE, US, NL, ...) |
| 🟡 Gelb | Unbekannte Region – auffällig, aber kein automatischer Alarm |
| ⬛ Dim | IP nicht auflösbar |

---

## Features im Detail <a name="features"></a>

### Baseline-Messung
Beim Start misst das Tool über `average_period` Sekunden den normalen Netzwerkverkehr. Dieser Wert dient als Referenz für alle späteren Alarme.

### Anomalie-Erkennung
Überschreitet der Traffic in einem Messintervall den Schwellenwert (`threshold %` über Baseline), wird das Gerät mit dem höchsten Traffic **im aktuellen Intervall** als Verursacher gemeldet.

### Port-Scan-Erkennung
Sendet eine IP innerhalb von 10 Sekunden Pakete an mehr als `portscan_limit` verschiedene Ports, wird ein Alarm ausgelöst.

### Whitelist
IPs auf der Whitelist lösen keinen Traffic-Alarm aus. Sie sind weiterhin im Dashboard sichtbar. Ideal für bekannte eigene Geräte oder Server.

### Blacklist
IPs auf der Blacklist lösen sofort einen Alarm aus, sobald ein Paket von ihnen empfangen wird.

---

## Häufige Fragen (FAQ) <a name="faq"></a>

**Das Dashboard startet, aber zeigt keine Pakete.**
→ Auf Linux/macOS: Sicherstellen dass das Tool mit `sudo` gestartet wird. Auf Windows: Als Administrator ausführen und Npcap installieren.

**Geo-IP zeigt überall `–`.**
→ Die `GeoLite2-City.mmdb` fehlt oder liegt nicht im Skript-Verzeichnis.

**Zu viele Alarme / zu wenige Alarme.**
→ Den `threshold`-Wert anpassen. Niedrig (5–15%) = empfindlicher, Hoch (30–50%) = toleranter.

**Kann ich nur ein bestimmtes Interface überwachen?**
→ Ja, den `interface`-Parameter in der Config auf den Interface-Namen setzen, z.B. `"eth0"` oder `"Wi-Fi"`.

**Wie deaktiviere ich den First-Run-Assistenten?**
→ Die Datei `.nm_setup_done` im Skript-Verzeichnis löschen, um ihn erneut zu starten – oder einfach stehenlassen, damit er nicht mehr erscheint.

---

*Net-Monitor ist ein Open-Source-Projekt und wird ohne Gewährleistung bereitgestellt.*
*Verwendung auf eigene Verantwortung – Paketerfassung nur in eigenen Netzwerken!*
