# Lab target image: the stock php:8.4.x-apache plus the page-cache
# eviction helper (sessdrop.c).
#
# PHP has no fadvise() of its own, so the phase-1 demo app spawns this
# helper while the victim request rewrites a session record: it drops the
# record's clean page cache in a loop, so the victim's pwrite re-creates -
# re-charges - those pages and the cgroup crosses its limit *inside* the
# splice window. This is the same eviction the local stage-2 controller
# performs with fadvise(2), reached over HTTP by the remote chain.
# Unprivileged: the helper only needs a read fd on the file.
ARG PHP_VERSION=8.4.27
FROM php:${PHP_VERSION}-apache

COPY sessdrop.c /tmp/sessdrop.c
RUN cc -O2 -o /usr/local/bin/sessdrop /tmp/sessdrop.c && rm /tmp/sessdrop.c
