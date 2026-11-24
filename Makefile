PY ?= python3
PROFILE ?= hybrid
PORT ?= 8884
N ?= 200

.PHONY: help certs up down bench-docker bench-local figures primitives capture report test clean

help:
	@echo "certs | up | down | bench-docker | bench-local | primitives | figures | capture PROFILE= PORT= | report | test"

certs:
	sh certs/gen_certs.sh

up: certs
	docker compose up -d --build mosquitto backend gateway-classical gateway-hybrid gateway-pqc

down:
	docker compose --profile edge down

# client runs in the CPU/RAM-limited `edge` container (EDGE_CPUS=0.1 make bench-docker for a slower node)
bench-docker:
	$(PY) bench/run_bench.py --mode docker -n $(N)

# gateways already listening on 127.0.0.1:8883/8884/8885 (e.g. from `make up`)
bench-local:
	$(PY) bench/run_bench.py --mode local -n $(N)

primitives:
	$(PY) bench/primitive_bench.py --iters 300

figures:
	$(PY) analysis/make_figures.py

capture:
	sudo sh capture/capture.sh $(PROFILE) $(PORT)

report: figures
	cd report && latexmk -pdf -interaction=nonstopmode report.tex

test:
	$(PY) -m unittest discover -s tests -v

clean:
	cd report && latexmk -C || true
	rm -rf results/*.csv results/*.json results/*.pcap
