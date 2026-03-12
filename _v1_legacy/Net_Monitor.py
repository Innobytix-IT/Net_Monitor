import time
from scapy.all import sniff, IP
from plyer import notification
import logging
import ctypes
import sys
import subprocess
from scapy.layers.inet import TCP, UDP

# Durchschnittliche Zeitperiode für den Netzwerkverkehr in Sekunden
average_traffic_period = 60
traffic_counter = 0

# Callback-Funktion für jedes empfangene Paket
def packet_callback(packet):
    global traffic_counter

    if IP in packet:
        # Erfassen der IP-Adresse des Pakets
        src_ip = packet[IP].src

        # Erfassen des Pakettyps (TCP oder UDP)
        packet_type = ""
        if TCP in packet:
            packet_type = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            packet_type = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            packet_type = "Other"
            src_port = ""
            dst_port = ""

        # Inkrementieren des Verkehrszählers
        traffic_counter += 1

        # Hinzufügen der Informationen in die Log-Datei
        log_message = f"Empfangenes Paket: IP={src_ip} | Typ={packet_type} | Quellport={src_port} | Zielport={dst_port}"
        logging.info(log_message)


# Funktion zum Überwachen des Netzwerkverkehrs
def monitor_network_traffic():
    global traffic_counter

    # Konfigurieren des Loggers
    logging.basicConfig(filename='lockdown.log', level=logging.INFO, format='%(asctime)s - %(message)s')

    #Begrüßung und Einleitung
    print('(C) 2023 Manuel Person "OpenPI Projekt"')
    print("")
    print("Willkommen beim Net-Monitor!")
    print("Bitte lesen Sie aufmerksam die README.md- Datei.")
    print("")
    print("Das Programm wird gleich gestartet...")
    print("")
    print("Bitte gedulden Sie sich einige Minuten, das Programm ermittelt gerade den durchschnittlichen Netzwerkverkehr.")
    print("Sobald der durchschnittliche Netzwerkverkehr ermittelt wurde öffnet sich die Netzwerkressourcen-Anzeige.")
    print("Bitte räumen Sie dem Programm die erforderlichen Rechte ein sobald Sie dazu aufgefordert werden sollten.")
    print("Bitte legen Sie auch gleich in diesem Eingabefenster den Schwellenwert für die Scanner- Sensitivität fest,\n sobald Sie dazu aufgefordert werden.")
    print("Nach dem Sie Ihren Schwellenwert definiert haben,\n wird das Programm mit einer kleinen Verzögerung hier in diesem Fenster mit der Messung beginnen.")
    print("\n")
    print("Bitte haben Sie noch einen kleinen Augenblick Geduld.")
    print("\n")

    # Durchschnittlichen Netzwerkverkehr berechnen
    start_time = time.time()

    # Netzwerkverkehr abfangen und die Callback-Funktion aufrufen
    sniff(filter="ip", prn=packet_callback, store=0, timeout=average_traffic_period)

    # Durchschnittlichen Netzwerkverkehr berechnen
    elapsed_time = time.time() - start_time
    average_traffic = traffic_counter / elapsed_time
    average_traffic = round(average_traffic, 2)  # Begrenzen auf zwei Dezimalstellen

    # Durchschnitt als Referenzwert für den Netzwerkverkehr verwenden
    print(f"Ihr Durchschnittlicher Netzwerkverkehr: {average_traffic} pps (Pakete pro Sekunde) ")
    print("\n")
    print("\n")

    # Administratorrechte bestätigen
    if not ctypes.windll.shell32.IsUserAnAdmin():
        # Falls nicht als Administrator ausgeführt, erneut als Administrator ausführen
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)

    # Windows Ressourcenmonitor aufrufen und Registerkarte "Netzwerk" öffnen
    subprocess.Popen(["perfmon", "/res"])

    # Schwellenwert abfragen
    print("Der Schwellenwert dient dazu, den aktuellen Netzwerkverkehr mit dem durchschnittlichen Netzwerkverkehr zu vergleichen\n und bei Bedarf eine Desktop- Warnmeldung auszugeben.")
    print("Der Benutzer wird aufgefordert, einen Schwellenwert einzugeben der angibt,\n um wie viel Prozent der aktuelle Netzwerkverkehr den durchschnittlichen Netzwerkverkehr überschreiten muss,\n um eine Warnmeldung auszulösen.")
    print("Wenn der aktuelle Netzwerkverkehr diesen Schwellenwert überschreitet, wird eine Benachrichtigung angezeigt,\n um auf eine potenzielle Netzwerküberlastung oder ungewöhnliche Aktivität hinzuweisen.")
    print("Durch die Eingabe des Schwellenwerts kann der Benutzer die Empfindlichkeit der Netzwerküberwachung anpassen.")
    print("Wir empfehlen je nach Art der Netzwerkumgebung einen Wert zwischen 5% und 25%.")
    print("\n")

    threshold = None
    while threshold is None:
        threshold_input = input("Bitte geben Sie den Sensitiv-Schwellenwert zwischen 1 und 100 ein (empfohlen 5-25 %): ")
        try:
            threshold = int(threshold_input)
            if not (1 <= threshold <= 100):
                raise ValueError
        except ValueError:
            print("Ungültige Eingabe. Bitte geben Sie eine Zahl zwischen 1 und 100 ein.")

    # Erstellen der Reportdatei
    report_file = open("network_traffic_report.txt", "w")
    report_file.write("Netzwerkverkehr Report\n")
    report_file.write("-----------------------\n\n")
    report_file.write("Durchschnittlicher Netzwerkverkehr: {} pps\n\n".format(average_traffic))
    report_file.write("Aktueller Netzwerkverkehr waehrend der Laufzeit:\n")

    while True:
        current_traffic = 0
        traffic_counter = 0

        # Durchschnittlichen Netzwerkverkehr überwachen
        start_time = time.time()

        # Netzwerkverkehr abfangen und die Callback-Funktion aufrufen
        sniff(filter="ip", prn=packet_callback, store=0, timeout=average_traffic_period)

        # Aktuellen Netzwerkverkehr berechnen
        elapsed_time = time.time() - start_time
        current_traffic = traffic_counter / elapsed_time
        current_traffic = round(current_traffic, 2)  # Begrenzen auf zwei Dezimalstellen

        # Überprüfen, ob der aktuelle Netzwerkverkehr den Schwellenwert übersteigt
        if current_traffic > average_traffic * (1 + threshold / 100):
            # Benachrichtigung anzeigen
            message = " Der Netzwerkverkehr übersteigt den Schwellenwert!"
            notification.notify(title="WARNUNG!", message=message, timeout=10)

            # Protokollieren der Aktivität in der Log-Datei
            log_message = f"{'Ich bin ein unnoetiger' if 'Bug im Code' in message else ''}Aktueller Netzwerkverkehr: {current_traffic} | Durchschnitt: {average_traffic}"
            logging.info(log_message)

        print(f"Aktueller Netzwerkverkehr: {current_traffic} pps")

        # Daten in die Reportdatei schreiben
        report_file.write("Zeitpunkt: {} - Aktueller Netzwerkverkehr: {}\n".format(time.strftime("%Y-%m-%d %H:%M:%S"), current_traffic))
        report_file.write("Schwellenwert in % angegeben: {}\n".format(threshold))
        report_file.flush()

    # Reportdatei schließen
    report_file.close()


# Netzwerkverkehr überwachen
monitor_network_traffic()
