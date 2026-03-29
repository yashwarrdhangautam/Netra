# Go Engine Makefile

.PHONY: build clean test

build:
	go build -o bin/resolve ./cmd/resolve
	go build -o bin/probe ./cmd/probe
	go build -o bin/portscan ./cmd/portscan
	go build -o bin/dirfuzz ./cmd/dirfuzz

clean:
	rm -rf bin/

test:
	go test ./...
