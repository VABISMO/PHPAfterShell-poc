.PHONY: up down test e2e clean

up:                    ## start the lab and wait until all healthchecks pass
	docker compose up -d --wait

down:                  ## stop the lab
	docker compose down

test:                  ## offline unit tests (no docker needed)
	python3 -m pytest tests/ -q

e2e:                   ## full local mirror of the CI sequence
	bash scripts/e2e-local.sh

clean:                 ## remove lab artifacts (sessions, results, stray shells)
	rm -rf sessions results app/s*.php
