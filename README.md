# Net_Monitor
Ein kostenloses Netzwerkanalyse und Überwachungstool mit Individuellen Einstellmöglichkeiten
# Net-Monitor - Netzwerküberwachungstool

Das Net-Monitor-Tool ermöglicht die Überwachung des Netzwerkverkehrs und die Benachrichtigung über potenzielle Netzwerküberlastungen oder ungewöhnliche Aktivitäten. Das Tool ermittelt den durchschnittlichen Netzwerkverkehr über einen fest definierten Zeitraum und vergleicht ihn mit dem aktuellen Netzwerkverkehr, um Abweichungen zu erkennen.

## Anleitung

### Ausführen des Programms:
1. Doppelklicken Sie auf die Datei "Net-Monitor.exe", um das Programm zu starten.
2. Das Programm wird automatisch gestartet und beginnt mit der Erfassung des Netzwerkverkehrs. Bitte haben Sie Geduld, während der durchschnittliche Netzwerkverkehr ermittelt wird.

### Überwachung des Netzwerkverkehrs:
- Das Programm überwacht kontinuierlich den Netzwerkverkehr und vergleicht ihn mit dem durchschnittlichen Netzwerkverkehr.
- Wenn der aktuelle Netzwerkverkehr den Schwellenwert überschreitet, wird eine Benachrichtigung angezeigt, um potenzielle Netzwerküberlastungen oder ungewöhnliche Aktivitäten anzuzeigen.
- Der aktuelle Netzwerkverkehr wird in Paketen pro Sekunde (pps) angezeigt.

### Log-Datei:
- Das Programm protokolliert alle empfangenen Pakete und andere relevante Informationen in einer Log-Datei mit dem Namen "lockdown.log".
- Die Log-Datei enthält Informationen wie die IP-Adresse des Pakets, den Pakettyp (TCP, UDP oder andere) und Zeitstempel.
- Die Log-Datei wird im gleichen Verzeichnis wie die "Net-Monitor.exe"-Datei gespeichert.

**Hinweis:** Das Programm erfordert Administratorrechte, um die Windows-Ressourcenmonitor-Anzeige zu öffnen. Stellen Sie sicher, dass Sie als Administrator ausgeführt werden.

### Report-Datei:
- Beim Start des Programms wird eine neue Report-Datei mit dem Namen "network_traffic_report.txt" erstellt. Falls bereits eine Datei mit diesem Namen vorhanden ist, wird sie überschrieben.
- Die Report-Datei enthält Informationen zum durchschnittlichen Netzwerkverkehr sowie den aktuellen Netzwerkverkehr während der Laufzeit des Programms.

Das Net-Monitor-Tool bietet eine einfache Möglichkeit, den Netzwerkverkehr zu überwachen und auf potenzielle Probleme oder ungewöhnliche Aktivitäten hinzuweisen. Es kann in verschiedenen Szenarien nützlich sein, z. B. zur Überwachung der Netzwerkauslastung in Heimnetzwerken, Büroumgebungen oder kleinen Unternehmen.

(C) 2023 Manuel Person 
