.PHONY: build test test-race vet fmt check scan clean

build:
	go build -trimpath -o bin/repodoctor ./cmd/repodoctor

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal

check:
	test -z "$$(gofmt -l cmd internal)"
	go vet ./...
	go test ./...
	go build ./...

scan: build
	./bin/repodoctor scan . --offline

clean:
	rm -rf bin dist coverage.out
