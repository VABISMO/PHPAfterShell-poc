# Security policy

## Supported versions

Only the latest revision of `main` is maintained. Pre-built lab states,
older PHP versions and third-party targets are out of scope.

## Reporting a vulnerability

- **In PHP itself** (the underlying session-handler bug,
  CVE-2026-126714): report it to the
  [PHP security team](https://www.php.net/security/) — not here.
  The fixed releases (8.2.36 / 8.3.37 / 8.4.28 / 8.5.13) are listed in
  the README.
- **In this repository** (the lab, the exploit scripts, CI): open a
  GitHub issue, or use a private security advisory if you believe the
  issue is sensitive.

## Scope and intent

This repository is an **educational proof of concept** for authorized
testing — see the [README disclaimer](README.md#disclaimer). It ships
exploit code on purpose; "this repository contains an exploit" is not a
vulnerability report.

Out of scope:

- misuse against systems you do not own or lack permission to test;
- findings that require modifying the bundled lab beyond its documented
  configuration (the lab is a fixture, not a product);
- vulnerability reports against the *upstream* CVE that belong with PHP
  itself (use the link above).

## Hardening the bundled lab

The lab binds every port to `127.0.0.1`, runs the targets inside
memory-bounded containers, and exposes no host filesystem to the target
beyond the documented bind mounts. If you find a way for the lab to
affect anything outside `127.0.0.1` / its containers, that *is* in scope —
please report it.
