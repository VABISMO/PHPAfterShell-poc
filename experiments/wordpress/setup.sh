#!/bin/sh
# Boot sequence for the WordPress lab target.
#
# The image's entrypoint only runs its init (skeleton copy + wp-config
# creation) when the first argument is apache2/php-fpm, so we invoke it
# with apache2-foreground in the BACKGROUND first, complete the WordPress
# install once it answers, and then hold the container on apache.
set -e

docker-entrypoint.sh apache2-foreground &
APACHE_PID=$!

echo "[lab] waiting for apache..."
# Answered-by check: WP canonicalises "/" to WP_URL (127.0.0.1:8091),
# a port nothing listens on INSIDE the container, so following the
# redirect always fails and this loop used to spin for the full 90s -
# leaving the OOM watchdog below inactive for a minute and a half after
# every recreate. Take the first response, redirect or not.
i=0
while [ "$i" -lt 90 ]; do
    if php -r '$c=stream_context_create(["http"=>["follow_location"=>0,"timeout"=>3]]); exit(@file_get_contents("http://127.0.0.1/",false,$c)===false?1:0);' 2>/dev/null; then
        break
    fi
    i=$((i + 1))
    sleep 1
done

cd /var/www/html
if ! wp core is-installed --allow-root 2>/dev/null; then
    echo "[lab] installing WordPress..."
    wp core install \
        --url="${WP_URL:-http://127.0.0.1:8091}" \
        --title="phpAfterShell lab" \
        --admin_user=admin \
        --admin_password=admin \
        --admin_email=admin@example.com \
        --skip-email \
        --allow-root
fi

# readiness marker for the container healthcheck + writable webroot for
# the gadget's shell (the exploit drops its file in the docroot)
touch /var/www/html/.lab-installed
chmod 777 /var/www/html
chmod 1777 /tmp
echo "[lab] ready"

# Hold the container on Apache - and bring it straight back if the master
# goes away. A bounded-memory target gets OOM-killed by design; without
# this loop the death of apache2-foreground would end the script, take the
# whole container down and cost a full re-bootstrap (~45s) every time. The
# other lab targets already run the same watchdog in their compose command.
while true; do
    if ! kill -0 "$APACHE_PID" 2>/dev/null; then
        echo "[lab] apache master gone - restarting"
        pkill -9 apache2 2>/dev/null || true
        rm -f /var/run/apache2/apache2.pid
        sleep 0.3
        docker-entrypoint.sh apache2-foreground &
        APACHE_PID=$!
        sleep 1
    fi
    sleep 1
done
