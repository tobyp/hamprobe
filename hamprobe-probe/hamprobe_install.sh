#!/bin/sh

if [ ! "$EUID" -eq "0" ]; then
	echo "This script must be run as root."
	exit 1;
fi

if pidof systemd > /dev/null; then
	systemctl is-active hamprobe && systemctl stop hamprobe;
else
	[ -f "/etc/init.d/hamprobe" ] && /etc/init.d/hamprobe stop;
fi

wget -O "/usr/local/bin/hamprobe_master.py" "http://api.hamprobe.net/assets/hamprobe_master.py"
chmod 744 "/usr/local/bin/hamprobe_master.py"

# Don't overwrite existing config (updating config format should be handled in hamprobe_probe)
if [ ! -f "/etc/hamprobe.conf" ]; then
	wget -O "/etc/hamprobe.conf" "http://api.hamprobe.net/assets/hamprobe.conf"
	chmod 600 "/etc/hamprobe.conf"
fi

if pidof systemd > /dev/null; then
	# Systemd
	wget -O "/etc/systemd/system/hamprobe.service" "http://api.hamprobe.net/assets/hamprobe.service"
	systemctl daemon-reload
	systemctl enable hamprobe
	systemctl start hamprobe

else
	# SysVInit
	wget -O "/etc/init.d/hamprobe" "http://api.hamprobe.net/assets/hamprobe.init"
	chmod +x "/etc/init.d/hamprobe"
	update-rc.d hamprobe defaults
	/etc/init.d/hamprobe start
fi
