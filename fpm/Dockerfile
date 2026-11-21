# nginx + php-fpm target for the phpAfterShell lab (the most common
# production pairing). One container = one memcg: the OOM interruption
# must cover nginx, php-fpm and the workers together.
FROM php:8.4.27-fpm

RUN apt-get update \
    && apt-get install -y --no-install-recommends nginx supervisor \
    && rm -rf /var/lib/apt/lists/*

# The lab's pool sizing mirrors the apache target: a pinned idle pool
# that forks on demand (the exploit holds ~10 concurrent connections).
COPY www.conf /usr/local/etc/php-fpm.d/zz-lab.conf

# FastCGI site. fastcgi_request_buffering off is THE critical setting:
# with nginx's default (on) the held filler bodies would be spooled by
# nginx to temp files (reclaimable page cache) instead of being buffered
# by PHP's RFC1867 parser in the worker - the exploit's pressure would
# evaporate. With off, the body streams into the worker exactly like
# mod_php does.
COPY nginx-site.conf /etc/nginx/sites-available/default

COPY supervisord.conf /etc/supervisor/conf.d/lab.conf

EXPOSE 80
# -n: stay in the foreground as PID 1 (Debian's default supervisord
# config would daemonize and the container would exit instantly)
CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/supervisord.conf"]
