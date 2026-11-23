# Joomla lab target for the phpAfterShell chain.
#
# Stock Joomla 5.2.1 on the official image's pinned PHP 8.2.27:
#   - PHP 8.2.27 is inside CVE-2026-126714's range (8.2 < 8.2.36); the
#     image was built 2024-12-25 and never re-pushed, so the tag is
#     reproducible and vulnerable;
#   - Joomla 5.2.1 is the LAST version where PHPGGC's Joomla/FW1
#     gadget works (3.9.0 <= 5.2.1; fixed in 5.2.2's __wakeup guard).
#
# The stock site is installed at FIRST BOOT by the official image's own
# env-driven CLI auto-installer (php installation/joomla.php install)
# against the joomla-db sidecar, and the lab's session component is
# installed through the image's OWN extension mechanism
# (JOOMLA_EXTENSIONS_PATHS -> cli/joomla.php extension:install) - see
# setup.sh.
FROM joomla:5.2.1-php8.2-apache

# The lab's session-using plugin, zipped so the official entrypoint's
# extension installer accepts it (it takes a file path).
COPY plg_system_labsession /tmp/plg_system_labsession
RUN php -r '$z = new ZipArchive(); $z->open("/opt/lab-labsession.zip", ZipArchive::CREATE | ZipArchive::OVERWRITE); foreach (["labsession.xml", "labsession.php"] as $f) { $z->addFile("/tmp/plg_system_labsession/" . $f, $f); } exit($z->close() ? 0 : 1);' \
    && rm -rf /tmp/plg_system_labsession

# Bounded-container Apache tuning (see the file's header): without it
# the prefork children accumulate allocator arenas and the rest charge
# drifts across attempts.
COPY apache-mcc.conf /etc/apache2/conf-available/zz-lab-mcc.conf
RUN a2enconf zz-lab-mcc

# Boot: official entrypoint (copy/install/extensions/serve) + the
# file-session config + readiness marker + OOM watchdog.
COPY setup.sh /usr/local/bin/lab-setup.sh
RUN chmod +x /usr/local/bin/lab-setup.sh
