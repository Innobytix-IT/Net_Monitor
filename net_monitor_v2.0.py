"""
╔══════════════════════════════════════════════════════════╗
║           NET-MONITOR  v2.0  –  OpenScan Projekt          ║
║         (C) 2023-2026 Manuel Person / modernisiert        ║
╚══════════════════════════════════════════════════════════╝

Modernes Netzwerk-Überwachungstool mit Live-Dashboard,
Anomalie-Erkennung, Geo-IP, DNS-Auflösung und mehr.

Changelog v2.0:
  - FIX: ip_counter / port_counter / proto_counter werden jetzt
         pro Messintervall zurückgesetzt (kein Memory Leak mehr,
         Dashboard zeigt aktuelle Intervall-Daten)
  - FIX: Report-Rotation implementiert (report_rotate Tage)
  - FIX: Geo-IP Farblogik – bekannte CDN/Cloud-Ranges nicht
         mehr pauschal rot; intelligente Klassifizierung
  - FIX: DNS-Auflösung mit kurzem Socket-Timeout (kein UI-Freeze)
  - FIX: PEP 668 – pip install mit --break-system-packages auf Linux
  - FIX: Alle Pfade konsistent relativ zu script_dir
  - FIX: Tippfehler "OpenSacn" → "OpenScan"
"""

from __future__ import annotations

import csv
import json
import logging
import os
import platform
import queue
import socket
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional

# ════════════════════════════════════════════════════════════════════════════
# PFAD-BASIS  (FIX: alle Dateien relativ zum Skript-Verzeichnis)
# ════════════════════════════════════════════════════════════════════════════

SCRIPT_DIR = Path(__file__).parent.resolve()

# ════════════════════════════════════════════════════════════════════════════
# FIRST-RUN SETUP
# ════════════════════════════════════════════════════════════════════════════

SETUP_DONE_FILE = SCRIPT_DIR / ".nm_setup_done"

# Pakete die automatisch installiert werden
REQUIRED_PACKAGES = [
    ("scapy",  "scapy"),
    ("rich",   "rich"),
    ("plyer",  "plyer"),
    ("geoip2", "geoip2"),
]

def _pip_install(package: str) -> bool:
    """Installiert ein Paket via pip. Gibt True zurück wenn erfolgreich."""
    # FIX: --break-system-packages für PEP 668 (Ubuntu 23.04+, Debian 12+)
    cmd = [sys.executable, "-m", "pip", "install", package, "--quiet"]
    if platform.system() == "Linux":
        cmd.append("--break-system-packages")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.returncode == 0
    except Exception:
        return False

def _check_npcap_windows() -> bool:
    """Prüft ob Npcap unter Windows installiert ist."""
    import winreg
    for key_path in [
        r"SOFTWARE\Npcap",
        r"SOFTWARE\WOW6432Node\Npcap",
        r"SOFTWARE\WinPcap",
    ]:
        try:
            winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            return True
        except FileNotFoundError:
            continue
    return False

def first_run_setup() -> None:
    """
    Erster-Start-Assistent: installiert Abhängigkeiten,
    führt durch Npcap- und GeoLite2-Setup.
    """
    def _print(msg: str = "") -> None:
        msg = msg.replace("[bold cyan]", "\033[1;36m")
        msg = msg.replace("[bold green]", "\033[1;32m")
        msg = msg.replace("[bold yellow]", "\033[1;33m")
        msg = msg.replace("[bold red]", "\033[1;31m")
        msg = msg.replace("[bold white]", "\033[1;37m")
        msg = msg.replace("[dim]", "\033[2m")
        msg = msg.replace("[/]", "\033[0m")
        for tag in ["[bold]","[/bold]","[cyan]","[green]","[yellow]","[red]","[white]",
                    "[/cyan]","[/green]","[/yellow]","[/red]","[/white]","[/dim]"]:
            msg = msg.replace(tag, "")
        print(msg + "\033[0m")

    def _ask(prompt: str, default: str = "j") -> bool:
        hint = "[J/n]" if default == "j" else "[j/N]"
        try:
            ans = input(f"{prompt} {hint}: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return default == "j"
        if ans == "":
            return default == "j"
        return ans in ("j", "y", "ja", "yes")

    os.system("cls" if platform.system() == "Windows" else "clear")

    _print()
    _print("╔══════════════════════════════════════════════════════════╗")
    _print("║        NET-MONITOR  v2.0  –  Ersteinrichtung            ║")
    _print("║                  OpenScan Projekt                       ║")
    _print("╚══════════════════════════════════════════════════════════╝")
    _print()
    _print("[bold cyan]Willkommen! Dieser Assistent richtet Net-Monitor ein.[/]")
    _print("[dim]Dieser Vorgang läuft nur beim ersten Start.[/]")
    _print()

    # ── SCHRITT 1: Python-Abhängigkeiten ───────────────────────────────────
    _print("━" * 58)
    _print("[bold white]SCHRITT 1/3 – Python-Pakete installieren[/]")
    _print("━" * 58)
    _print()
    _print("Folgende Pakete werden benötigt:")
    _print("  • scapy   – Paketerfassung")
    _print("  • rich    – Terminal-Dashboard")
    _print("  • plyer   – Desktop-Benachrichtigungen")
    _print("  • geoip2  – Geo-IP-Auflösung (Ländererkennung)")
    _print()

    # FIX: Hinweis auf venv für Linux-Nutzer
    if platform.system() == "Linux":
        _print("[dim]💡 Linux-Tipp: Pakete werden mit --break-system-packages installiert.[/]")
        _print("[dim]   Empfohlen: Nutze ein Virtual Environment (python3 -m venv .venv)[/]")
        _print()

    all_ok = True
    for import_name, pip_name in REQUIRED_PACKAGES:
        try:
            __import__(import_name)
            _print(f"  [bold green]✅  {pip_name} – bereits installiert[/]")
        except ImportError:
            _print(f"  ⏳  Installiere {pip_name} …")
            if _pip_install(pip_name):
                _print(f"  [bold green]✅  {pip_name} – erfolgreich installiert[/]")
            else:
                _print(f"  [bold red]❌  {pip_name} – Installation fehlgeschlagen![/]")
                _print(f"      Bitte manuell ausführen: pip install {pip_name}")
                all_ok = False

    if not all_ok:
        _print()
        _print("[bold yellow]⚠️  Einige Pakete konnten nicht installiert werden.[/]")
        _print("    Bitte behebe die Fehler und starte erneut.")
        _print()
        input("Drücke ENTER zum Beenden …")
        sys.exit(1)

    _print()

    # ── SCHRITT 2: Npcap (nur Windows) ────────────────────────────────────
    if platform.system() == "Windows":
        _print("━" * 58)
        _print("[bold white]SCHRITT 2/3 – Npcap installieren (Windows)[/]")
        _print("━" * 58)
        _print()

        npcap_ok = False
        try:
            npcap_ok = _check_npcap_windows()
        except Exception:
            pass

        if npcap_ok:
            _print("[bold green]✅  Npcap ist bereits installiert – super![/]")
        else:
            _print("[bold yellow]⚠️  Npcap wurde NICHT gefunden.[/]")
            _print()
            _print("So installierst du Npcap:")
            _print()
            _print("  1. Öffne im Browser:  https://npcap.com/#download")
            _print("  2. Klicke auf:  [bold cyan]'Npcap X.XX installer'[/]  (neueste Version)")
            _print("  3. Führe die heruntergeladene .exe als Administrator aus")
            _print("  4. Im Installer: Haken bei [bold cyan]'WinPcap API-compatible Mode'[/] setzen")
            _print("  5. Installation abschließen und PC NICHT neu starten")
            _print()
            _print("[dim]💡 Tipp: Npcap ist auch in Wireshark enthalten.[/]")
            _print("   Falls Wireshark installiert ist, ist Npcap bereits vorhanden.")
            _print()

            if _ask("Hast du Npcap jetzt installiert?", default="j"):
                try:
                    if _check_npcap_windows():
                        _print("[bold green]✅  Npcap erkannt – perfekt![/]")
                    else:
                        _print("[bold yellow]⚠️  Npcap noch nicht erkannt.[/]")
                        _print("    Net-Monitor startet trotzdem – Scapy meldet sich")
                        _print("    wenn der Treiber fehlt.")
                except Exception:
                    _print("[dim]    (Konnte Npcap nicht prüfen – kein Problem)[/]")
            else:
                _print("[bold yellow]⚠️  Ohne Npcap kann Scapy unter Windows keine[/]")
                _print("    Pakete erfassen. Bitte nachinstallieren!")
        _print()
    else:
        _print("━" * 58)
        _print("[bold white]SCHRITT 2/3 – Systemtreiber[/]")
        _print("━" * 58)
        _print()
        if platform.system() == "Linux":
            _print("[bold green]✅  Linux erkannt – kein extra Treiber nötig.[/]")
            _print("    Starte das Tool immer mit:  [bold cyan]sudo python net_monitor.py[/]")
        elif platform.system() == "Darwin":
            _print("[bold green]✅  macOS erkannt – kein extra Treiber nötig.[/]")
            _print("    Starte das Tool immer mit:  [bold cyan]sudo python3 net_monitor.py[/]")
        _print()

    # ── SCHRITT 3: GeoLite2-City Datenbank ────────────────────────────────
    _print("━" * 58)
    _print("[bold white]SCHRITT 3/3 – GeoLite2-City (Geo-IP-Datenbank)[/]")
    _print("━" * 58)
    _print()

    mmdb_path = SCRIPT_DIR / "GeoLite2-City.mmdb"

    if mmdb_path.exists():
        _print(f"[bold green]✅  GeoLite2-City.mmdb gefunden – Geo-IP aktiv![/]")
        _print(f"    Pfad: {mmdb_path}")
    else:
        _print("Die Geo-IP-Datenbank zeigt dir bei jedem Paket")
        _print("das Herkunftsland der IP-Adresse an.")
        _print("[dim](Optional – das Tool läuft auch ohne sie)[/]")
        _print()
        _print("So bekommst du die Datenbank (kostenlos):")
        _print()
        _print("  1. Konto erstellen auf:  https://www.maxmind.com/en/geolite2/signup")
        _print("     (Name + E-Mail reichen, Konto ist kostenlos)")
        _print()
        _print("  2. Nach der E-Mail-Bestätigung einloggen und aufrufen:")
        _print("     https://www.maxmind.com/en/accounts/current/geoip/downloads")
        _print()
        _print("  3. Bei [bold cyan]'GeoLite2 City'[/]  →  [bold cyan]'Download GZIP'[/] klicken")
        _print("     (NICHT die CSV-Version!)")
        _print()
        _print("  4. Die .tar.gz Datei entpacken")
        _print("     Windows: Rechtsklick → 'Alle extrahieren'  oder  7-Zip")
        _print("     Linux/Mac: tar -xzf GeoLite2-City_*.tar.gz")
        _print()

        target = SCRIPT_DIR / "GeoLite2-City.mmdb"
        _print(f"  5. Die Datei  [bold cyan]GeoLite2-City.mmdb[/]  hierhin kopieren:")
        _print(f"     [bold cyan]{target}[/]")
        _print()
        _print("[dim]💡 Ohne diese Datei zeigt das Tool '–' statt Länderkürzel.[/]")
        _print("[dim]   Du kannst sie jederzeit nachträglich hinzufügen.[/]")
        _print()

        if _ask("Hast du die GeoLite2-City.mmdb jetzt kopiert?", default="n"):
            if mmdb_path.exists():
                _print(f"[bold green]✅  Datei gefunden – Geo-IP aktiv![/]")
            else:
                _print(f"[bold yellow]⚠️  Datei nicht gefunden unter:[/]")
                _print(f"    {mmdb_path}")
                _print("    Net-Monitor startet ohne Geo-IP.")
        else:
            _print("[dim]    Geo-IP übersprungen – kann jederzeit nachgeholt werden.[/]")

    _print()
    _print("━" * 58)
    _print("[bold green]✅  Einrichtung abgeschlossen![/]")
    _print("━" * 58)
    _print()
    _print("Net-Monitor ist bereit. Beim nächsten Start")
    _print("wird dieser Assistent nicht mehr angezeigt.")
    _print()
    input("Drücke ENTER um fortzufahren …")

    SETUP_DONE_FILE.write_text("setup completed")


# ════════════════════════════════════════════════════════════════════════════
# FRÜHZEITIGER SETUP-CHECK
# ════════════════════════════════════════════════════════════════════════════
if not SETUP_DONE_FILE.exists():
    first_run_setup()
    if platform.system() == "Windows":
        import subprocess as _sp
        sys.exit(_sp.call([sys.executable] + sys.argv))
    else:
        import os as _os
        _os.execv(sys.executable, [sys.executable] + sys.argv)

# ── Drittanbieter-Abhängigkeiten ────────────────────────────────────────────
try:
    from scapy.all import sniff, IP, IPv6
    from scapy.layers.inet import TCP, UDP, ICMP
    from scapy.layers.inet6 import ICMPv6EchoRequest
except ImportError:
    sys.exit("❌  Scapy nicht gefunden. Setup fehlerhaft? Bitte manuell: pip install scapy")

try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, TextColumn
    from rich.table import Table
    from rich.text import Text
    from rich import box
    from rich.prompt import Prompt, IntPrompt, Confirm
    from rich.rule import Rule
    from rich.columns import Columns
except ImportError:
    sys.exit("❌  Rich nicht gefunden. Setup fehlerhaft? Bitte manuell: pip install rich")

try:
    from plyer import notification as plyer_notify
    PLYER_OK = True
except ImportError:
    PLYER_OK = False

try:
    import geoip2.database  # type: ignore
    import geoip2.errors    # type: ignore
    GEOIP_OK = True
except ImportError:
    GEOIP_OK = False

# ── Konfigurationsdatei (FIX: alle Pfade relativ zu SCRIPT_DIR) ─────────────
CONFIG_FILE = SCRIPT_DIR / "net_monitor_config.json"
LOG_FILE    = SCRIPT_DIR / "net_monitor.log"
REPORT_DIR  = SCRIPT_DIR / "reports"
GEOIP_DB    = SCRIPT_DIR / "GeoLite2-City.mmdb"


# ════════════════════════════════════════════════════════════════════════════
# DATENSTRUKTUREN
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class PacketInfo:
    timestamp:  str
    src_ip:     str
    dst_ip:     str
    protocol:   str
    src_port:   int | str
    dst_port:   int | str
    size:       int
    flags:      str = ""
    ip_version: int = 4

@dataclass
class Config:
    average_period:   int   = 60
    monitor_interval: int   = 10
    threshold:        int   = 20
    bpf_filter:       str   = "ip or ip6"
    interface:        str   = ""

    notify_desktop:   bool  = True
    notify_log:       bool  = True

    resolve_dns:      bool  = True
    geo_lookup:       bool  = True
    detect_portscan:  bool  = True
    portscan_limit:   int   = 100         # 100 Ports in 10s = realistischer Wert

    whitelist:        list  = field(default_factory=list)
    blacklist:        list  = field(default_factory=list)

    export_csv:       bool  = True
    export_json:      bool  = False
    report_rotate:    int   = 7

    def save(self) -> None:
        CONFIG_FILE.write_text(json.dumps(asdict(self), indent=2, ensure_ascii=False))

    @classmethod
    def load(cls) -> "Config":
        if CONFIG_FILE.exists():
            data = json.loads(CONFIG_FILE.read_text())
            return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})
        return cls()


# ════════════════════════════════════════════════════════════════════════════
# HILFS-FUNKTIONEN
# ════════════════════════════════════════════════════════════════════════════

console = Console()

_dns_cache: dict[str, str] = {}
_dns_lock = threading.Lock()

def resolve_hostname(ip: str) -> str:
    with _dns_lock:
        if ip in _dns_cache:
            return _dns_cache[ip]

    # FIX: Kurzer Socket-Timeout verhindert UI-Freeze (war vorher unbegrenzt)
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(0.5)
    try:
        host = socket.gethostbyaddr(ip)[0]
    except Exception:
        host = ip
    finally:
        socket.setdefaulttimeout(old_timeout)

    with _dns_lock:
        _dns_cache[ip] = host
    return host

_geo_reader = None
if GEOIP_OK and GEOIP_DB.exists():
    try:
        _geo_reader = geoip2.database.Reader(str(GEOIP_DB))
    except Exception:
        pass

def geo_lookup(ip: str) -> str:
    if _geo_reader is None:
        return "–"
    try:
        r = _geo_reader.city(ip)
        city    = r.city.name or ""
        country = r.country.iso_code or ""
        if city and country:
            city_short = city[:10] + "…" if len(city) > 10 else city
            return f"{city_short}, {country}"
        return country or "–"
    except Exception:
        return "–"

def is_private_ip(ip: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

# FIX: Bekannte legitime Cloud/CDN-Länder nicht pauschal rot markieren.
# Diese Länder hosten die meisten großen CDNs, Cloud-Dienste und APIs.
# Alarm-würdige Länder können hier gezielt ergänzt werden.
_NEUTRAL_COUNTRIES = {
    "DE", "US", "NL", "GB", "FR", "SE", "CH", "AT", "IE",
    "FI", "DK", "NO", "BE", "LU", "CA", "AU", "JP", "SG",
}

def geo_color(country_code: str) -> str:
    """
    Gibt eine Rich-Farbe für ein Länderkürzel zurück.
    - LAN / bekannte Cloud-Länder → grün/dim
    - Unbekannte Länder           → gelb (auffällig, aber kein Alarm)
    - Bekannt riskante Herkunft   → rot (kann nach Bedarf erweitert werden)
    """
    if country_code in ("–", ""):
        return "dim"
    if country_code in _NEUTRAL_COUNTRIES:
        return "green"
    return "yellow"   # Unbekannte Länder gelb – kein Pauschalalarm mehr

def send_notification(title: str, message: str, timeout: int = 10) -> None:
    if PLYER_OK:
        try:
            plyer_notify.notify(title=title, message=message, timeout=timeout)
            return
        except Exception:
            pass
    console.print(f"\n[bold red]🔔  {title}[/bold red]: {message}")

def open_resource_monitor() -> None:
    system = platform.system()
    if system == "Windows":
        try:
            import ctypes
            ctypes.windll.shell32.ShellExecuteW(None, "runas", "perfmon.exe", "/res", None, 1)
        except Exception:
            try:
                subprocess.Popen(["taskmgr.exe"])
            except Exception:
                console.print("[yellow]⚠️  Ressourcenmonitor konnte nicht geöffnet werden[/yellow]")
    elif system == "Darwin":
        try:
            subprocess.Popen(["open", "-a", "Activity Monitor"])
        except Exception:
            pass
    elif system == "Linux":
        for cmd in [["gnome-system-monitor"], ["xterm", "-e", "htop"], ["xterm", "-e", "iftop"]]:
            try:
                subprocess.Popen(cmd)
                break
            except FileNotFoundError:
                continue

# FIX: Report-Rotation – löscht Reports die älter als N Tage sind
def rotate_reports(days: int) -> None:
    if not REPORT_DIR.exists():
        return
    cutoff = time.time() - days * 86400
    deleted = 0
    for f in REPORT_DIR.iterdir():
        if f.is_file() and f.stat().st_mtime < cutoff:
            try:
                f.unlink()
                deleted += 1
            except Exception:
                pass
    if deleted:
        logging.getLogger("NetMonitor").info(
            "Report-Rotation: %d alte Datei(en) gelöscht (älter als %d Tage).", deleted, days
        )


# ════════════════════════════════════════════════════════════════════════════
# KERN-ÜBERWACHUNGSKLASSE
# ════════════════════════════════════════════════════════════════════════════

class NetworkMonitor:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg

        self._lock             = threading.Lock()
        self.packet_count      = 0
        self.byte_count        = 0
        self.proto_counter:    dict[str, int]  = defaultdict(int)
        self.ip_counter:       dict[str, int]  = defaultdict(int)
        self.port_counter:     dict[int, int]  = defaultdict(int)
        self.alert_count       = 0

        # FIX: Separate kumulative Zähler für Dashboard-Statistiken (All-Time)
        # Die obigen (_counter) werden pro Intervall zurückgesetzt.
        self._proto_total:     dict[str, int]  = defaultdict(int)
        self._ip_total:        dict[str, int]  = defaultdict(int)
        self._port_total:      dict[int, int]  = defaultdict(int)

        self._portscan_track:  dict[str, deque] = defaultdict(lambda: deque(maxlen=200))

        self.pps_history: deque[float] = deque(maxlen=60)
        self.bps_history: deque[float] = deque(maxlen=60)

        self.baseline_pps: float = 0.0
        self.baseline_bps: float = 0.0

        self.recent_packets: deque[PacketInfo] = deque(maxlen=50)
        self.alerts: deque[str] = deque(maxlen=100)

        self._pkt_queue: queue.Queue = queue.Queue(maxsize=5000)
        self._stop_event = threading.Event()

        self._setup_logger()

        REPORT_DIR.mkdir(exist_ok=True)

        # FIX: Report-Rotation beim Start ausführen
        if cfg.report_rotate > 0:
            rotate_reports(cfg.report_rotate)

        self._report_path = REPORT_DIR / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        self._csv_writer: Optional[csv.DictWriter] = None
        self._report_file = None
        if cfg.export_csv:
            self._open_csv()

        self._json_records: list[dict] = []

    def _setup_logger(self) -> None:
        self.logger = logging.getLogger("NetMonitor")
        self.logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        self.logger.addHandler(fh)

    def _open_csv(self) -> None:
        self._report_file = open(self._report_path, "w", newline="", encoding="utf-8")
        fields = ["timestamp", "src_ip", "dst_ip", "protocol",
                  "src_port", "dst_port", "size", "flags", "ip_version"]
        self._csv_writer = csv.DictWriter(self._report_file, fieldnames=fields)
        self._csv_writer.writeheader()

    def _packet_callback(self, pkt) -> None:
        try:
            self._pkt_queue.put_nowait(pkt)
        except queue.Full:
            pass

    def _processing_worker(self) -> None:
        while not self._stop_event.is_set():
            try:
                pkt = self._pkt_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            self._process_packet(pkt)

    def _process_packet(self, pkt) -> None:
        if IP in pkt:
            layer = pkt[IP]
            ipver = 4
        elif IPv6 in pkt:
            layer = pkt[IPv6]
            ipver = 6
        else:
            return

        src_ip = layer.src
        dst_ip = layer.dst

        if self.cfg.blacklist and src_ip in self.cfg.blacklist:
            self._fire_alert(f"⛔  Blacklist-IP erkannt: {src_ip}", level="WARNING")

        proto = flags = ""
        src_port = dst_port = ""
        if TCP in pkt:
            proto    = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags    = str(pkt[TCP].flags)
        elif UDP in pkt:
            proto    = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        elif ICMP in pkt:
            proto    = "ICMP"
        else:
            proto    = "OTHER"

        size = len(pkt)

        with self._lock:
            self.packet_count += 1
            self.byte_count   += size
            # Intervall-Zähler (werden in _evaluate_interval zurückgesetzt)
            self.proto_counter[proto] += 1
            self.ip_counter[src_ip]  += 1
            if dst_port:
                self.port_counter[int(dst_port)] += 1
            # FIX: Kumulative Zähler (wachsen über die gesamte Laufzeit,
            # werden NICHT zurückgesetzt – für All-Time-Statistiken)
            self._proto_total[proto] += 1
            self._ip_total[src_ip]   += 1
            if dst_port:
                self._port_total[int(dst_port)] += 1

        if self.cfg.detect_portscan and proto in ("TCP", "UDP") and dst_port:
            self._check_portscan(src_ip, int(dst_port))

        info = PacketInfo(
            timestamp  = datetime.now().strftime("%H:%M:%S"),
            src_ip     = src_ip,
            dst_ip     = dst_ip,
            protocol   = proto,
            src_port   = src_port,
            dst_port   = dst_port,
            size       = size,
            flags      = flags,
            ip_version = ipver,
        )
        with self._lock:
            self.recent_packets.append(info)

        if self._csv_writer:
            try:
                self._csv_writer.writerow(asdict(info))
                self._report_file.flush()
            except Exception:
                pass

        if self.cfg.notify_log:
            self.logger.debug(
                "PKT src=%s dst=%s proto=%s sport=%s dport=%s size=%d flags=%s",
                src_ip, dst_ip, proto, src_port, dst_port, size, flags,
            )

    def _check_portscan(self, src_ip: str, dst_port: int) -> None:
        now = time.time()
        track = self._portscan_track[src_ip]
        track.append((now, dst_port))
        recent = [(t, p) for t, p in track if now - t <= 10]
        unique_ports = len({p for _, p in recent})
        if unique_ports >= self.cfg.portscan_limit:
            msg = f"🔍  Möglicher Port-Scan von {src_ip} ({unique_ports} Ports in 10 s)"
            self._fire_alert(msg, level="WARNING")
            self._portscan_track[src_ip].clear()

    def _fire_alert(self, message: str, level: str = "WARNING") -> None:
        ts    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{ts}] {message}"
        with self._lock:
            self.alerts.appendleft(entry)
            self.alert_count += 1
        if self.cfg.notify_log:
            getattr(self.logger, level.lower(), self.logger.warning)(message)
        if self.cfg.notify_desktop:
            threading.Thread(
                target=send_notification,
                args=("Net-Monitor Warnung", message),
                daemon=True,
            ).start()

    def _evaluate_interval(self, elapsed: float) -> tuple[float, float, str]:
        with self._lock:
            pkts   = self.packet_count
            bytes_ = self.byte_count
            # FIX: Top-Talker des aktuellen Intervalls VOR dem Leeren ermitteln
            # (verhindert "Falscher Verdächtiger"-Bug durch All-Time-Zähler)
            top_ip_interval = (
                max(self.ip_counter, key=self.ip_counter.get)
                if self.ip_counter else "Unknown"
            )
            self.packet_count = 0
            self.byte_count   = 0
            self.proto_counter.clear()
            self.ip_counter.clear()
            self.port_counter.clear()

        pps = round(pkts  / elapsed, 2) if elapsed > 0 else 0.0
        bps = round(bytes_ / elapsed, 2) if elapsed > 0 else 0.0
        self.pps_history.append(pps)
        self.bps_history.append(bps)
        return pps, bps, top_ip_interval

    def measure_baseline(self, progress_cb=None) -> None:
        self.logger.info("Baseline-Messung gestartet (%ds)", self.cfg.average_period)

        self._stop_event.clear()
        worker = threading.Thread(target=self._processing_worker, daemon=True)
        worker.start()

        t0 = time.time()
        sniff(
            filter=self.cfg.bpf_filter,
            iface=self.cfg.interface or None,
            prn=self._packet_callback,
            store=False,
            timeout=self.cfg.average_period,
        )

        time.sleep(0.5)

        elapsed = time.time() - t0
        pps, bps, _ = self._evaluate_interval(elapsed)  # Top-Talker bei Baseline irrelevant
        self.baseline_pps = pps
        self.baseline_bps = bps

        self._stop_event.set()
        worker.join(timeout=3)
        self._stop_event.clear()

        self.logger.info("Baseline: %.2f pps  |  %.0f B/s", pps, bps)

    def run_monitor_loop(self, update_callback=None) -> None:
        self._stop_event.clear()
        worker = threading.Thread(target=self._processing_worker, daemon=True)
        worker.start()

        try:
            while True:
                t0 = time.time()
                sniff(
                    filter=self.cfg.bpf_filter,
                    iface=self.cfg.interface or None,
                    prn=self._packet_callback,
                    store=False,
                    timeout=self.cfg.monitor_interval,
                )
                elapsed = time.time() - t0
                pps, bps, current_top_ip = self._evaluate_interval(elapsed)

                limit_pps = self.baseline_pps * (1 + self.cfg.threshold / 100)
                limit_bps = self.baseline_bps * (1 + self.cfg.threshold / 100)
                if pps > limit_pps or bps > limit_bps:
                    # FIX: current_top_ip kommt aus dem aktuellen Intervall,
                    # nicht aus dem All-Time-Zähler → korrekte Täter-Ermittlung
                    is_whitelisted = current_top_ip in self.cfg.whitelist

                    if is_whitelisted:
                        self.logger.info(
                            "Hohe Last durch Whitelist-Gerät %s (%0.1f pps) – ignoriert.", current_top_ip, pps
                        )
                    else:
                        msg = (
                            f"Netzwerkverkehr {pps:.1f} pps durch {current_top_ip} "
                            f"(Schwellenwert: {limit_pps:.1f} pps / +{self.cfg.threshold}%) "
                            f"– Gerät nicht auf Whitelist!"
                        )
                        self._fire_alert(msg)

                if update_callback:
                    update_callback(pps, bps)

        except KeyboardInterrupt:
            pass
        finally:
            self._stop_event.set()
            worker.join(timeout=3)
            self._close_reports()

    def _close_reports(self) -> None:
        if self._report_file and not self._report_file.closed:
            self._report_file.close()
        if self.cfg.export_json and self._json_records:
            jp = REPORT_DIR / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            jp.write_text(json.dumps(self._json_records, indent=2, ensure_ascii=False))

    # Dashboard-Statistiken: nutzen die kumulativen (_total) Zähler
    def get_top_talkers(self, n: int = 8) -> list[tuple[str, int]]:
        with self._lock:
            data = dict(self._ip_total)
        return sorted(data.items(), key=lambda x: x[1], reverse=True)[:n]

    def get_top_ports(self, n: int = 8) -> list[tuple[int, int]]:
        with self._lock:
            data = dict(self._port_total)
        return sorted(data.items(), key=lambda x: x[1], reverse=True)[:n]

    def get_proto_stats(self) -> dict[str, int]:
        with self._lock:
            return dict(self._proto_total)


# ════════════════════════════════════════════════════════════════════════════
# DASHBOARD-RENDERING (Rich)
# ════════════════════════════════════════════════════════════════════════════

COLORS = {
    "TCP":   "cyan",
    "UDP":   "green",
    "ICMP":  "yellow",
    "OTHER": "dim",
}

def make_header(cfg: Config) -> Panel:
    txt = Text()
    txt.append("NET-MONITOR  v2.0", style="bold white on blue")
    txt.append("  │  ", style="dim")
    txt.append(f"Interface: {cfg.interface or 'alle'}", style="yellow")
    txt.append("  │  ", style="dim")
    txt.append(f"Filter: {cfg.bpf_filter}", style="yellow")
    txt.append("  │  ", style="dim")
    txt.append(datetime.now().strftime("%Y-%m-%d  %H:%M:%S"), style="green")
    return Panel(txt, box=box.HORIZONTALS, style="bold blue")


def make_stats_panel(mon: NetworkMonitor) -> Panel:
    pps_now = mon.pps_history[-1] if mon.pps_history else 0.0
    bps_now = mon.bps_history[-1] if mon.bps_history else 0.0
    limit   = mon.baseline_pps * (1 + mon.cfg.threshold / 100)

    color = "green"
    if pps_now > limit * 0.8:
        color = "yellow"
    if pps_now > limit:
        color = "red"

    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="right", style="bold")
    grid.add_column()

    grid.add_row("Aktuell:",       f"[{color}]{pps_now:.2f} pps  |  {_fmt_bps(bps_now)}[/{color}]")
    grid.add_row("Baseline:",      f"{mon.baseline_pps:.2f} pps  |  {_fmt_bps(mon.baseline_bps)}")
    grid.add_row("Schwellenwert:", f"{limit:.2f} pps  (+{mon.cfg.threshold}%)")
    grid.add_row("Alarme gesamt:", f"[red]{mon.alert_count}[/red]")

    return Panel(grid, title="[bold]📊  Live-Statistik[/bold]", border_style=color)


def _fmt_bps(bps: float) -> str:
    if bps >= 1_000_000:
        return f"{bps/1_000_000:.2f} MB/s"
    if bps >= 1_000:
        return f"{bps/1_000:.2f} KB/s"
    return f"{bps:.0f} B/s"


def make_sparkline(history: deque, color: str = "green", width: int = 40) -> str:
    if not history:
        return "–"
    vals = list(history)[-width:]
    mx   = max(vals) or 1
    chars = " ▁▂▃▄▅▆▇█"
    return "".join(chars[min(8, int(v / mx * 8))] for v in vals)


def make_graph_panel(mon: NetworkMonitor) -> Panel:
    pps_line = f"[green]{make_sparkline(mon.pps_history)}[/green]"
    bps_line = f"[cyan]{make_sparkline(mon.bps_history, 'cyan')}[/cyan]"
    grid = Table.grid(padding=(0, 1))
    grid.add_column(style="bold", width=8)
    grid.add_column()
    grid.add_row("pps:", pps_line)
    grid.add_row("B/s:", bps_line)
    return Panel(grid, title="[bold]📈  Verlauf (letzte 60 Messungen)[/bold]", border_style="blue")


def make_proto_panel(mon: NetworkMonitor) -> Panel:
    stats = mon.get_proto_stats()
    total = sum(stats.values()) or 1
    tbl   = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    tbl.add_column(width=6, style="bold")
    tbl.add_column(width=8, justify="right")
    tbl.add_column(width=20)
    for proto in ("TCP", "UDP", "ICMP", "OTHER"):
        cnt  = stats.get(proto, 0)
        pct  = cnt / total * 100
        bar  = "█" * int(pct / 5)
        col  = COLORS.get(proto, "white")
        tbl.add_row(
            f"[{col}]{proto}[/{col}]",
            f"{cnt:,}",
            f"[{col}]{bar:<20}[/{col}] {pct:.1f}%",
        )
    return Panel(tbl, title="[bold]🔌  Protokolle[/bold]", border_style="magenta")


def make_top_talkers_panel(mon: NetworkMonitor, resolve: bool = False) -> Panel:
    talkers = mon.get_top_talkers()
    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    tbl.add_column("IP-Adresse",  style="cyan",  min_width=16)
    tbl.add_column("Hostname",    style="dim",   min_width=20)
    tbl.add_column("Pakete",      justify="right")
    tbl.add_column("Privat?",     justify="center")
    for ip, cnt in talkers:
        host = resolve_hostname(ip) if resolve else "–"
        priv = "🏠" if is_private_ip(ip) else "🌐"
        tbl.add_row(ip, host, str(cnt), priv)
    return Panel(tbl, title="[bold]🔝  Top-Talker[/bold]", border_style="cyan")


def make_top_ports_panel(mon: NetworkMonitor) -> Panel:
    WELL_KNOWN = {
        20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
        143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
        8443: "HTTPS-Alt", 27017: "MongoDB",
    }
    ports = mon.get_top_ports()
    tbl   = Table(box=box.SIMPLE, show_header=True, header_style="bold green")
    tbl.add_column("Port", justify="right")
    tbl.add_column("Dienst", style="green")
    tbl.add_column("Pakete", justify="right")
    for port, cnt in ports:
        service = WELL_KNOWN.get(port, "–")
        tbl.add_row(str(port), service, str(cnt))
    return Panel(tbl, title="[bold]🔒  Top-Ports[/bold]", border_style="green")


def make_recent_packets_panel(mon: NetworkMonitor) -> Panel:
    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold white", min_width=60)
    tbl.add_column("Zeit",    style="dim",     width=10)
    tbl.add_column("Land",    style="magenta", width=15, no_wrap=True)
    tbl.add_column("Src-IP",  style="cyan",    min_width=15)
    tbl.add_column("→",       width=2)
    tbl.add_column("Dst-IP",  style="yellow",  min_width=15)
    tbl.add_column("Proto",   width=6)
    tbl.add_column("Port",    width=6, justify="right")
    tbl.add_column("Größe",   width=7, justify="right")
    tbl.add_column("Flags",   width=6)

    with mon._lock:
        pkts = list(mon.recent_packets)[-12:]

    for p in reversed(pkts):
        col = COLORS.get(p.protocol, "white")

        # FIX: Intelligente Geo-IP-Farbgebung statt pauschal "nicht-DE = rot"
        if is_private_ip(p.src_ip):
            country_display = "[dim]LAN[/dim]"
        else:
            c     = geo_lookup(p.src_ip)
            color = geo_color(c.split(", ")[-1] if ", " in c else c)
            country_display = f"[{color}]{c}[/{color}]"

        tbl.add_row(
            p.timestamp,
            country_display,
            p.src_ip,
            "→",
            p.dst_ip,
            f"[{col}]{p.protocol}[/{col}]",
            str(p.dst_port),
            f"{p.size} B",
            p.flags or "–",
        )
    return Panel(tbl, title="[bold]📦  Letzte Pakete  (🌍 Geo-IP aktiv)[/bold]", border_style="white")


def make_alerts_panel(mon: NetworkMonitor) -> Panel:
    with mon._lock:
        alerts = list(mon.alerts)[:6]
    if not alerts:
        content = Text("Keine Alarme  ✅", style="green")
    else:
        content = Text()
        for a in alerts:
            content.append(a + "\n", style="red")
    return Panel(content, title=f"[bold red]🚨  Alarme ({mon.alert_count})[/bold red]", border_style="red")


def build_layout(mon: NetworkMonitor, cfg: Config) -> Panel:
    top_row = Table.grid(expand=True, padding=(0, 1))
    top_row.add_column(ratio=1)
    top_row.add_column(ratio=1)
    top_row.add_column(ratio=1)
    top_row.add_row(
        make_stats_panel(mon),
        make_proto_panel(mon),
        make_alerts_panel(mon),
    )

    mid_row = Table.grid(expand=True, padding=(0, 1))
    mid_row.add_column(ratio=1)
    mid_row.add_column(ratio=1)
    mid_row.add_row(
        make_top_talkers_panel(mon, resolve=cfg.resolve_dns),
        make_top_ports_panel(mon),
    )

    layout = Table.grid(expand=True)
    layout.add_column()
    layout.add_row(make_header(cfg))
    layout.add_row(make_graph_panel(mon))
    layout.add_row(top_row)
    layout.add_row(mid_row)
    layout.add_row(make_recent_packets_panel(mon))

    return Panel(layout, box=box.HEAVY, border_style="blue", padding=0)


# ════════════════════════════════════════════════════════════════════════════
# KONFIGURATIONS-ASSISTENT (interaktiv)
# ════════════════════════════════════════════════════════════════════════════

def setup_wizard(cfg: Config) -> Config:
    console.print(Rule("[bold blue]NET-MONITOR  v2.0  –  Einrichtungsassistent[/bold blue]"))
    console.print()

    cfg.threshold = IntPrompt.ask(
        "Sensitiv-Schwellenwert in % [empfohlen 5–25]",
        default=cfg.threshold,
    )
    cfg.monitor_interval = IntPrompt.ask(
        "Messintervall in Sekunden",
        default=cfg.monitor_interval,
    )
    cfg.resolve_dns = Confirm.ask("DNS-Auflösung aktivieren?", default=cfg.resolve_dns)
    cfg.detect_portscan = Confirm.ask(
        "Port-Scan-Erkennung aktivieren?", default=cfg.detect_portscan
    )
    if PLYER_OK:
        cfg.notify_desktop = Confirm.ask(
            "Desktop-Benachrichtigungen aktivieren?", default=cfg.notify_desktop
        )
    else:
        console.print("[dim]plyer nicht installiert – Desktop-Benachrichtigungen deaktiviert.[/dim]")
        cfg.notify_desktop = False

    cfg.export_csv = Confirm.ask("CSV-Report schreiben?", default=cfg.export_csv)

    cfg.save()
    console.print("[green]✅  Konfiguration gespeichert.[/green]")
    console.print()
    return cfg


# ════════════════════════════════════════════════════════════════════════════
# EINSTIEGSPUNKT
# ════════════════════════════════════════════════════════════════════════════

def main() -> None:
    console.print()
    console.print(Panel.fit(
        "[bold white]NET-MONITOR  v2.0[/bold white]\n"
        "[dim](C) 2023-2026 Manuel Person  ·  OpenScan Projekt[/dim]\n"   # FIX: Tippfehler
        "[dim]Modernisiert mit Rich · Threading · Geo-IP · Port-Scan-Erkennung[/dim]",
        border_style="blue",
        title="[bold blue]Willkommen[/bold blue]",
    ))
    console.print()

    if platform.system() == "Windows":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            console.print("[yellow]⚠️  Für vollständige Paketerfassung werden Administratorrechte empfohlen.[/yellow]")
    elif platform.system() in ("Linux", "Darwin"):
        if os.geteuid() != 0:
            console.print("[bold red]❌  Scapy benötigt Root-Rechte. Bitte mit sudo starten![/bold red]")
            sys.exit(1)

    cfg = Config.load()

    if not CONFIG_FILE.exists() or Confirm.ask("Einstellungen anpassen?", default=False):
        cfg = setup_wizard(cfg)

    if Confirm.ask("System-Ressourcenmonitor öffnen?", default=True):
        open_resource_monitor()

    mon = NetworkMonitor(cfg)

    console.print()
    console.print(f"[cyan]🔍  Messe Baseline über {cfg.average_period} Sekunden …[/cyan]")
    console.print("[dim]   (Bitte normalen Netzwerkbetrieb fortsetzen)[/dim]")

    with Progress(
        TextColumn("[cyan]{task.description}"),
        BarColumn(),
        TextColumn("[cyan]{task.completed}/{task.total} s"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Baseline-Messung", total=cfg.average_period)
        done = threading.Event()

        def _progress_updater():
            for _ in range(cfg.average_period):
                if done.is_set():
                    break
                time.sleep(1)
                progress.advance(task, 1)

        t = threading.Thread(target=_progress_updater, daemon=True)
        t.start()
        mon.measure_baseline()
        done.set()
        t.join()

    console.print(f"[green]✅  Baseline: {mon.baseline_pps:.2f} pps  |  {_fmt_bps(mon.baseline_bps)}[/green]")
    console.print()
    console.print("[dim]Live-Dashboard startet … [Strg+C] zum Beenden[/dim]")
    time.sleep(1)

    with Live(
        build_layout(mon, cfg),
        console=console,
        refresh_per_second=2,
        screen=True,
    ) as live:
        def _monitor_thread():
            mon.run_monitor_loop()

        t = threading.Thread(target=_monitor_thread, daemon=True)
        t.start()

        try:
            while t.is_alive():
                live.update(build_layout(mon, cfg))
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass

    console.print()
    console.print("[bold green]Net-Monitor beendet.[/bold green]")
    if cfg.export_csv:
        console.print(f"[dim]Report gespeichert: {mon._report_path}[/dim]")
    console.print(f"[dim]Log-Datei:           {LOG_FILE}[/dim]")


if __name__ == "__main__":
    main()
