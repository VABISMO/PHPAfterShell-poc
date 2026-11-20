# Contributors

Thanks goes to everyone who works on PHPAfterShell-poc.

## Core contributors

| Name | Area |
| --- | --- |
| PHPAfterShell-poc maintainers | exploit chain, lab, CI |

## Founding research credit

The vulnerability itself — **CVE-2026-126714 (phpAfterShell)** — was
discovered and disclosed by the security research team at
[depthfirst](https://depthfirst.com/research/phpaftershell) (Yuhang Wu et al.)
in coordinated disclosure with the PHP security team (fix published
2026-11-19). This repository is an independent educational proof of concept
built on top of their published advisory.

## Contributing

1. Fork and create a feature branch.
2. Keep the offline unit tests green: `python -m pytest tests/ -q`.
3. If you touch the exploit logic, run the bundled lab end to end:
   `docker compose up -d && python poc/stage1_splice.py`.
4. Open a pull request with a clear description of the change.

Bug reports and improvements are welcome. Please do **not** submit weaponized
variants aimed at third-party systems — this project exists for authorized
testing, education and defensive research.
