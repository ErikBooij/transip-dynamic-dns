.PHONY: build
build:
	go build main.go

.PHONY: build-docker
build-docker:
	docker build . -t erikbooij/transip-dynamic-dns:latest

.PHONY: run
run: build
	./main

.PHONY: run-docker
run-docker:
	docker run --rm erikbooij/transip-dynamic-dns:latest