#!/bin/sh
# 허용 호스트(쉼표 구분, ALLOW_HOSTS)만 CONNECT/프록시를 허용하는 tinyproxy를 띄운다.
set -eu
: "${ALLOW_HOSTS:?ALLOW_HOSTS가 필요하다}"
: > /tmp/allow
echo "$ALLOW_HOSTS" | tr ',' '\n' | sed 's/\./\\./g; s/^/^/; s/$/$/' > /tmp/allow
cat > /tmp/tinyproxy.conf <<CONF
Port 3128
Listen 0.0.0.0
Timeout 60
LogLevel Info
Syslog Off
LogFile "/tmp/tinyproxy.log"
PidFile "/tmp/tinyproxy.pid"
Allow 0.0.0.0/0
ConnectPort 443
ConnectPort 80
FilterType ere
FilterDefaultDeny Yes
Filter "/tmp/allow"
CONF
exec tinyproxy -d -c /tmp/tinyproxy.conf
