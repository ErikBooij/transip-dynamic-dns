TAG_VERSION := 1.0.2

.PHONY: build
build:
	go build main.go

.PHONY: build-docker
build-docker:
	docker build . -t erikbooij/transip-dynamic-dns:latest && \
	docker build . -t erikbooij/transip-dynamic-dns:$(TAG_VERSION)

.PHONY: push-docker
push-docker:
	docker push erikbooij/transip-dynamic-dns:latest && \
	docker push erikbooij/transip-dynamic-dns:$(TAG_VERSION)

.PHONY: run
run: build
	./main

.PHONY: run-docker
run-docker:
	docker run --rm erikbooij/transip-dynamic-dns:latest