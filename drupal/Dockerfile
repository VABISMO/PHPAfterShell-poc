# Drupal 7 lab target for the phpAfterShell chain.
#
# Stock Drupal 7.98 (the upper bound of PHPGGC's Drupal7/RCE1 chain)
# on a PHP that is itself vulnerable to CVE-2026-126714 (8.2 < 8.2.36).
# The site is installed at first boot over HTTP by setup.sh driving
# Drupal's own installer - no database server: SQLite (Drupal ships
# the driver, PDO SQLite is in the stock image).
FROM php:8.2.33-apache

# Drupal's hard requirement beyond the stock image: GD (the installer
# refuses to proceed without it).
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpng-dev libjpeg62-turbo-dev \
    && docker-php-ext-configure gd --with-jpeg \
    && docker-php-ext-install gd \
    && rm -rf /var/lib/apt/lists/*

# Drupal 7.98 - the version PHPGGC's Drupal7/RCE1 chain advertises as
# its upper bound (7.0.8 <= 7.98): newer7.x releases add a cache_form
# guard to DrupalCacheArray::__destruct that the chain depends on
# being absent (measured).
ADD https://ftp.drupal.org/files/projects/drupal-7.98.tar.gz /tmp/drupal.tar.gz
RUN tar -xzf /tmp/drupal.tar.gz -C /var/www/html --strip-components=1 \
    && rm /tmp/drupal.tar.gz \
    && rm -f /var/www/html/index.html

# Stock php.net installs do not load opcache (the image enables it);
# Drupal 7's install batch is known to break under it - see the file.
COPY opcache-off.ini /usr/local/etc/php/conf.d/zz-opcache-off.ini

# Site directory the installer expects: writable files dir + the stock
# settings.php (the installer itself writes the database config into
# it; setup.sh appends the lab's session component after the install).
COPY settings-lab-snippet.php /tmp/lab-settings-snippet.php
RUN mkdir -p /var/www/html/sites/default/files \
    && cp /var/www/html/sites/default/default.settings.php \
          /var/www/html/sites/default/settings.php \
    && chown -R www-data:www-data /var/www/html/sites/default

# The installer itself: drives Drupal's own web installer over HTTP
# (the same requests a browser sends) with a throwaway Apache - at
# BUILD time, where there is no cgroup limit: the stock install peaks
# at ~118 MiB (measured), which would OOM-kill an Apache child inside
# a bounded container. The lab's session component is appended after
# the install (the installer rewrites settings.php while writing the
# database config), and the readiness marker is baked in.
COPY install.php /usr/local/bin/drupal-install.php
RUN chmod +x /usr/local/bin/drupal-install.php \
    && (docker-php-entrypoint apache2-foreground >/dev/null 2>&1 &) \
    && i=0; while [ "$i" -lt 60 ]; do \
         if php -r 'exit(@file_get_contents("http://127.0.0.1/install.php")===false?1:0);' 2>/dev/null; then break; fi; \
         i=$((i+1)); sleep 1; \
       done \
    && php /usr/local/bin/drupal-install.php \
    && cat /tmp/lab-settings-snippet.php >> /var/www/html/sites/default/settings.php \
    && chown www-data:www-data /var/www/html/sites/default/settings.php \
    && touch /var/www/html/.lab-installed \
    && pkill -9 apache2 || true

# Bounded-container Apache tuning (see the file's header): without it
# the prefork children accumulate allocator arenas and the rest charge
# drifts past the landable band within a few attempts.
COPY apache-mcc.conf /etc/apache2/conf-available/zz-lab-mcc.conf
RUN a2enconf zz-lab-mcc

# Boot: hold Apache under an OOM watchdog (the same pattern as the
# other lab targets - a bounded target gets OOM-killed by design).
COPY setup.sh /usr/local/bin/lab-setup.sh
RUN chmod +x /usr/local/bin/lab-setup.sh
