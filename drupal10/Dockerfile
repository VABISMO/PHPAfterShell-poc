# Drupal 10 lab target for the phpAfterShell chain.
#
# Stock Drupal 10.6.17 on the official image: PHP 8.3.35 (built
# 2026-09-25, before the advisory) is inside CVE-2026-126714's range
# (8.3 < 8.3.37). The chain plants PHPGGC Guzzle/FW1 - Guzzle ships
# with Drupal core (verified: FileCookieJar autoloads and
# --test-payload triggers against THIS image); the other modern-Drupal
# chain (Drupal9/RCE1) does NOT work on D10/11 because it needs
# laminas/diactoros, which D10 no longer bundles (measured).
FROM drupal:10.6.17-php8.3-apache

# The lab's session component, appended to settings.php after the
# stock install (the installer owns that file until then).
COPY settings-lab-snippet.php /tmp/lab-settings-snippet.php

# First boot equivalent: drive Drupal's own web installer over HTTP at
# BUILD time (where no cgroup limit applies - same reasoning as the
# Drupal 7 target), then append the session component and bake the
# readiness marker. The webroot must be writable: the gadget's file
# write lands there (same rationale as the other targets).
COPY install.php /usr/local/bin/drupal10-install.php
COPY apache-mcc.conf /etc/apache2/conf-available/zz-lab-mcc.conf
RUN chmod +x /usr/local/bin/drupal10-install.php \
    && a2enconf zz-lab-mcc \
    && chown -R www-data:www-data /opt/drupal/web \
    && (docker-php-entrypoint apache2-foreground >/dev/null 2>&1 &) \
    && i=0; while [ "$i" -lt 60 ]; do \
         if php -r 'exit(@file_get_contents("http://127.0.0.1/core/install.php")===false?1:0);' 2>/dev/null; then break; fi; \
         i=$((i + 1)); sleep 1; \
       done \
    && php /usr/local/bin/drupal10-install.php \
    && cat /tmp/lab-settings-snippet.php >> /var/www/html/sites/default/settings.php \
    && chown www-data:www-data /var/www/html/sites/default/settings.php \
    && touch /var/www/html/.lab-installed \
    && pkill -9 apache2 || true

# Boot: hold Apache under an OOM watchdog (the same pattern as the
# other lab targets).
COPY setup.sh /usr/local/bin/lab-setup.sh
RUN chmod +x /usr/local/bin/lab-setup.sh
