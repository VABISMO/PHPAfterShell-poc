# ThinkPHP lab target for the phpAfterShell chain.
#
# Stock ThinkPHP 6.1.5 (measured: PHPGGC ThinkPHP/RCE3 triggers
# against it with --test-payload; RCE3/RCE4 are advertised for
# -6.0.1+, but RCE4 does not fire on 6.1.5 - measured) on a PHP that
# is itself vulnerable to CVE-2026-126714 (8.2 < 8.2.36). The app is
# created at build time - no database, no install-on-boot: the only
# routes the chain touches never query one.
FROM php:8.2.33-apache

# ThinkPHP requirements beyond the stock image: mbstring, and the
# zip/git toolchain composer wants for dist archives.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git unzip libzip-dev libonig-dev \
    && docker-php-ext-install mbstring zip \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# Stock ThinkPHP into the docroot. Composer's security-advisory
# blocking is disabled: this IS a deliberately vulnerable lab target
# (we run an affected PHP on purpose) and ThinkPHP itself carries open
# advisories - same rationale as the Laravel target. Scripts are
# skipped (the skeleton's post-autoload script breaks on newer PHP
# than the target's); service discovery - which the app does need -
# is then run explicitly on the target's own PHP.
RUN rm -rf /var/www/html/* \
    && composer config -g policy.advisories.block false \
    && COMPOSER_NO_SCRIPTS=1 composer create-project --no-interaction \
        --prefer-dist topthink/think /var/www/html "6.1.*" \
    && cd /var/www/html \
    && COMPOSER_NO_SCRIPTS=1 composer require --no-interaction \
        topthink/framework:6.1.5 \
    && php think service:discover \
    && chown -R www-data:www-data /var/www/html

# The entry point: global middleware that uses NATIVE PHP sessions -
# representing the very common class of integrations that do the same
# (carts, SSO bridges, ...). ThinkPHP's own think\session\Store never
# touches PHP's session module, so the native session runs
# independently: it starts one and stores one user-submitted field;
# it reports nothing and provides no endpoint or diagnostic. See
# app/middleware/NativeSession.php.
COPY middleware.php /var/www/html/app/middleware.php
COPY NativeSession.php /var/www/html/app/middleware/NativeSession.php
RUN chown www-data:www-data /var/www/html/app/middleware.php \
        /var/www/html/app/middleware/NativeSession.php

# Serve ThinkPHP the way ThinkPHP is always served: DocumentRoot =
# public/ (the framework's own router and .htaccess live there).
COPY apache-allowoverride.conf /etc/apache2/conf-available/zz-lab-allowoverride.conf
RUN sed -i 's|DocumentRoot /var/www/html$|DocumentRoot /var/www/html/public|' \
        /etc/apache2/sites-available/000-default.conf \
    && a2enconf zz-lab-allowoverride && a2enmod rewrite

# Bounded-container Apache tuning (see the file's header): without it
# the prefork children accumulate allocator arenas and the rest charge
# drifts across attempts.
COPY apache-mcc.conf /etc/apache2/conf-available/zz-lab-mcc.conf
RUN a2enconf zz-lab-mcc

# Boot: hold Apache under an OOM watchdog (the same pattern as the
# other lab targets - a bounded target gets OOM-killed by design).
COPY setup.sh /usr/local/bin/lab-setup.sh
RUN chmod +x /usr/local/bin/lab-setup.sh
