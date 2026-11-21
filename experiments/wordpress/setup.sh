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
i=0
while [ "$i" -lt 90 ]; do
    if php -r 'exit(@file_get_contents("http://127.0.0.1/")===false?1:0);' 2>/dev/null; then
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

wait "$APACHE_PID"
