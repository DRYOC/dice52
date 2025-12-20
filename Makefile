.PHONY: all fmt tidy build run clean test
.PHONY: rust-build rust-test rust-run rust-clean rust-fmt
.PHONY: all-build all-test all-clean

# Default: build both
all: fmt tidy rust-fmt

# ============== Go Targets ==============

init:
	go mod init dice52

fmt:
	go fmt ./...

tidy:
	go mod tidy

build:
	go build -o bin/dice52 cmd/dice52/main.go

run:
	./dice52

clean:
	rm -f dice52

test:
	go test ./...

# ============== Rust Targets ==============

rust-fmt:
	cargo fmt

rust-build:
	cargo build --release

rust-test:
	cargo test

rust-run:
	cargo run --bin dice52-demo

rust-clean:
	cargo clean

rust-bench:
	cargo bench

rust-doc:
	cargo doc --open

# ============== Combined Targets ==============

all-build: build rust-build

all-test: test rust-test

all-clean: clean rust-clean
