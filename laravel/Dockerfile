# Laravel lab target for the phpAfterShell chain.
#
# Stock Laravel 11 on a PHP that is itself vulnerable to
# CVE-2026-126714 (8.4 < 8.4.28). The app is created at build time -
# no database, no install-on-boot: the only routes the chain touches
# (GET / consumer, POST /bio carrier payload) never touch the DB.
FROM php:8.4.27-apache

# Laravel requirements beyond the stock image: mbstring (strings),
# xml (DOM), zip (composer archives), onig/libxml/libzip headers
RUN apt-get update && apt-get install -y --no-install-recommends \
        git unzip libzip-dev libonig-dev libxml2-dev \
    && docker-php-ext-install mbstring xml zip \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# Stock Laravel into the docroot, configured for this lab:
# - APP_KEY generated (Laravel encrypts cookies without it)
# - sqlite (no database server; nothing in the chain queries it)
# - composer's security-advisory blocking is disabled: this IS a
#   deliberately vulnerable lab target (we run affected PHP on purpose)
#   and every current framework release carries open advisories
RUN rm -rf /var/www/html/* \
    && composer config -g policy.advisories.block false \
    && composer create-project --no-interaction --prefer-dist \
        laravel/laravel /var/www/html "^11.0" \
    && cd /var/www/html \
    && sed -i 's/^DB_CONNECTION=.*/DB_CONNECTION=sqlite/' .env \
    && sed -i 's|^DB_DATABASE=.*|DB_DATABASE=/var/www/html/database/database.sqlite|' .env \
    && touch database/database.sqlite \
    && php artisan key:generate --force \
    && chown -R www-data:www-data /var/www/html

# The entry point: a route middleware that uses NATIVE PHP sessions -
# representing the very common class of Laravel packages that do the
# same (carts, session-based auth bridges, ...). It starts a session
# and stores one user-submitted field; it reports nothing and provides
# no endpoint or diagnostic. See routes/web.php.
COPY routes-web.php /var/www/html/routes/web.php
RUN chown www-data:www-data /var/www/html/routes/web.php

# Boot: apache in the background (the image entrypoint still does its
# init for an apache2-foreground argument), mark readiness, hold.
COPY setup.sh /usr/local/bin/lab-setup.sh
RUN chmod +x /usr/local/bin/lab-setup.sh
