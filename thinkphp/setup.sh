#!/bin/sh
# Boot sequence for the ThinkPHP lab target.
#
# The app is fully created at build time (no install step); this only
# needs apache up and a readiness marker - the same pattern as the
# Laravel target.
set -e

docker-php-entrypoint apache2-foreground &
APACHE_PID=$!

echo "[lab] waiting for apache..."
i=0
while [ "$i" -lt 90 ]; do
    if php -r 'exit(@file_get_contents("http://127.0.0.1/")===false?1:0);' 2>/dev/null; then
        break
    fi
    i=$((i + 1))
    sleep 1
done

touch /var/www/html/.lab-installed
chmod 1777 /tmp
echo "[lab] ready"

while true; do
    if ! kill -0 "$APACHE_PID" 2>/dev/null; then
        echo "[lab] apache master gone - restarting"
        pkill -9 apache2 2>/dev/null || true
        rm -f /var/run/apache2/apache2.pid
        sleep 0.3
        docker-php-entrypoint apache2-foreground &
        APACHE_PID=$!
        sleep 1
    fi
    sleep 1
done
