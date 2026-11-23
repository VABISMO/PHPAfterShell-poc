#!/bin/sh
# Boot sequence for the Drupal lab target.
#
# The site is installed at BUILD time (see the Dockerfile - the stock
# install peaks at ~118 MiB, far above any sane runtime limit), so
# this only needs to hold Apache under an OOM watchdog: a bounded
# target gets OOM-killed by design and must come back in 1-2 s, not
# vanish (the same pattern the other lab targets use).
set -e

docker-php-entrypoint apache2-foreground &
APACHE_PID=$!

echo "[lab] waiting for apache..."
i=0
while [ "$i" -lt 90 ]; do
    if php -r 'exit(@file_get_contents("http://127.0.0.1/install.php")===false?1:0);' 2>/dev/null; then
        break
    fi
    i=$((i + 1))
    sleep 1
done

chmod 1777 /tmp
# no session residue from a previous container generation (they live
# in the container's writable layer)
rm -f /tmp/sess_* 2>/dev/null || true
# readiness marker (baked in at build time; touch keeps the contract
# explicit for the healthcheck)
touch /var/www/html/.lab-installed
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
