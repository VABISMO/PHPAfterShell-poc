#!/bin/sh
# Boot sequence for the Laravel lab target.
#
# The app is fully created at build time (no install step); this only
# needs apache up and a readiness marker. The image's entrypoint is
# docker-php-entrypoint (the PHP images', not the WordPress one's) and
# only runs its init for an apache2/php-fpm first argument - hence we
# invoke it with apache2-foreground in the background and hold on it.
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

# writable webroot for the gadget's shell + readiness marker for the
# container healthcheck
chmod 777 /var/www/html
touch /var/www/html/.lab-installed
chmod 1777 /tmp
echo "[lab] ready"

wait "$APACHE_PID"
