#!/bin/sh
# Boot sequence for the Joomla lab target.
#
# The official image's entrypoint does the stock first-boot work when
# run with its normal argument: copy the app into the webroot, create
# the database, run the env-driven CLI auto-installer, install the
# extensions listed in JOOMLA_EXTENSIONS_PATHS (the lab's session
# component travels that official mechanism) and only then exec Apache
# - so "the port answers with the DB host in configuration.php" implies
# "the site and the component are installed".
#
# Then one configuration line: Joomla's own documented
# `session_handler` option, database -> file. Sessions are then plain
# PHP file sessions (the only storage the session splice can ever
# reach), which is also what a real site chooses when it does not want
# session traffic in the database. Finally: readiness marker + the
# OOM watchdog the other lab targets use.
set -e

/entrypoint.sh apache2-foreground &
APACHE_PID=$!

echo "[lab] waiting for apache + stock install..."
i=0
installed=0
while [ "$i" -lt 180 ]; do
    if php -r 'exit(@fsockopen("127.0.0.1", 80)?0:1);' 2>/dev/null; then
        if grep -q "joomla-db" /var/www/html/configuration.php 2>/dev/null; then
            installed=1
            break
        fi
    fi
    i=$((i + 1))
    sleep 1
done
if [ "$installed" != "1" ]; then
    echo "[lab] ERROR: stock install did not complete"
    exit 1
fi

if [ ! -f /var/www/html/.lab-installed ]; then
    echo "[lab] session_handler: database -> filesystem (stock Joomla option)"
    sed -i "s/public \$session_handler = 'database';/public \$session_handler = 'filesystem';/" \
        /var/www/html/configuration.php
    chown www-data:www-data /var/www/html/configuration.php

    # The official extension installer installs the lab component but
    # leaves it unpublished (Joomla's stock behaviour for installed
    # plugins) - publish it the same way the admin UI would: one row in
    # the extensions table, then clear the cache.
    echo "[lab] publishing the lab_session plugin"
    php -r '
    $host = getenv("JOOMLA_DB_HOST") ?: "joomla-db";
    $name = getenv("JOOMLA_DB_NAME") ?: "joomla";
    $user = getenv("JOOMLA_DB_USER") ?: "joomla";
    $pass = getenv("JOOMLA_DB_PASSWORD") ?: "joomla";
    $db = new PDO("mysql:host=$host;dbname=$name", $user, $pass);
    $n = $db->exec("UPDATE joom_extensions SET enabled=1 WHERE element='"'"'labsession'"'"' AND type='"'"'plugin'"'"'");
    echo "[lab] enabled rows: $n\n";
    ' || { echo "[lab] ERROR: could not publish the plugin"; exit 1; }
    php cli/joomla.php cache:clean >/dev/null 2>&1 || true

    touch /var/www/html/.lab-installed
fi

chmod 1777 /tmp
echo "[lab] ready"

while true; do
    if ! kill -0 "$APACHE_PID" 2>/dev/null; then
        echo "[lab] apache master gone - restarting"
        pkill -9 apache2 2>/dev/null || true
        rm -f /var/run/apache2/apache2.pid
        sleep 0.3
        /entrypoint.sh apache2-foreground &
        APACHE_PID=$!
        sleep 1
    fi
    sleep 1
done
