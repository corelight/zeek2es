#!/bin/bash

ZEEK2ES=~/zeek2es.py

echo "Processing file: " $1;
if [[ $1 =~ ^.*/(amqp|bgp|conn|dce|dhcp|dns|dpd|file|ftp|icmp|irc|ipsec|http|kerberos|ldap|mount|mysql|ntlm|ntp|openvpn|portmap|nfs|notice|radius|rfb|rdp|reporter|rip|sip|smb|smtp|snmp|socks|spicy|ssh|ssl|stun|syslog|tftp|tunnel|vpn|weird|wireguard|x509).*\.log\.gz$ ]]
then
        echo $'\tLaunching zeek2es.py for: ' $1;
        python3 $ZEEK2ES $@
fi