# WordPress lab target: the newest WordPress for which a public CORE
# gadget chain exists (PHPGGC WordPress/RCE2, 6.4.0-6.4.1) on a PHP
# version that is itself vulnerable to CVE-2026-126714 (8.2 < 8.2.36).
#
# The chain uses WordPress's OWN class (WP_HTML_Token): its __destruct
# calls $this->on_destroy($this->bookmark_name) - no lab-provided
# gadget is involved anywhere in the chain.
FROM wordpress:6.4.1-php8.2-apache

# wp-cli for the idempotent first-boot install (see setup.sh)
ADD https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar /usr/local/bin/wp
RUN chmod +x /usr/local/bin/wp

# Baked into the SKELETON directory: the image's entrypoint copies the
# skeleton into the (volume-backed) docroot on first boot, carrying the
# mu-plugin with it - no fragile runtime file mounts.
COPY lab-session.php /usr/src/wordpress/wp-content/mu-plugins/lab-session.php

COPY setup.sh /usr/local/bin/lab-setup.sh
RUN chmod +x /usr/local/bin/lab-setup.sh
