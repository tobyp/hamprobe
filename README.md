## Vermessung des HAMNET

[Homepage](http://hamprobe.net) | [Graphen](http://hamprobe.net/grafana) | [Dumps](http://hamprobe.net/dumps)

Das [HAMNET](https://hamnetdb.net) ist ein diverses, verteiltes, Funknetzwerk das von Funkamateuren betrieben und verwaltet wird.

Zur Analyse der Eigenschaften dieses Netzes sollen Messproben verteilt, mit diesen Messungen angestellt, und die Ergebnisse analysiert werden. Die Erkenntnisse werden auf der [HAMNET-Tagung 2017](http://www.hamnettagung.de/) präsentiert.

## Probe

 - Die [Software](https://github.com/tobyp/hamprobe) ist Open Source, wird öffentlich entwickelt, und läuft auf allen Platformen, die Python 3 unterstützen (mit besonderem Augenmerk auf Raspberry Pi/Beaglebone).
 - Gemessen werden erstmal Links (Latenz, Bandbreite, Verlustraten) und Topologie (Netzdichte, Netzelastizität, Routenstabilität).
 - Die Daten sind für jedermann [einsehbar](http://hamprobe.net/grafana) und [runterladbar](http://hamprobe.net/dumps), die Ergebnisse werden anschließend auch veröffentlicht.

## Installation

Die Software kann auf jedem unix-artigen System laufen, das Python 3 hat und ans HAMNET angeschlossen ist.
Es werden root-Rechte benötigt, weil auf rohe ICMP sockets zugegriffen wird.

__*Die Software enthält einen optionalen Auto-Updater, damit Paketverlust- und Bandbreitentests nachgeliefert werden können.*__

### Installation mit Auto-Updater

    wget "http://api.hamprobe.net/assets/hamprobe_install.sh" && chmod +x "./hamprobe_install.sh" && "./hamprobe_install.sh"

### Installation ohne Auto-Updater

Bald kann der Installer auch ohne Auto-Updater installieren. Bis dahin sind folgende Schritte notwendig:

 1. Config-Datei laden <http://api.hamprobe.net/assets/hamprobe.conf> (wird jedes mal mit eigener unique-ID und Key generiert)
 2. In der Config `interval_update_check` auf 0 setzen
 3. HAMprobe Probe herunterladen <http://api.hamprobe.net/assets/hamprobe_probe.py>
 4. Als root starten (am besten per init/rc.d/systemd): `hamprobe_probe.py --config hamprobe.conf` (Pfade anpassen)

### Troubleshooting

Sowohl Master als auch Probe geben viel debug Information aus, wenn man in der config unter `logging`/`loggers`/`hamprobe` das `level` auf `DEBUG` stellt.
