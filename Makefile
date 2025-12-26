.PHONY: all fmt tidy build run clean test
.PHONY: rust-build rust-test rust-run rust-clean rust-fmt
.PHONY: all-build all-test all-clean

# Default: build both
all: fmt tidy rust-fmt

# ============== Go Targets ==============

fmt:
	cd clients/golang && go fmt ./...

tidy:
	cd clients/golang && go mod tidy

build:
	cd clients/golang && go build -o bin/dice52 cmd/dice52/main.go

run:
	cd clients/golang && ./bin/dice52

clean:
	rm -f clients/golang/bin/dice52

test:
	cd clients/golang && go test ./...

# ============== Rust Targets ==============

rust-fmt:
	cd clients/rust && cargo fmt

rust-build:
	cd clients/rust && cargo build --release

rust-test:
	cd clients/rust && cargo test

rust-run:
	cd clients/rust && cargo run --bin dice52-demo

rust-clean:
	cd clients/rust && cargo clean

rust-bench:
	cd clients/rust && cargo bench

rust-doc:
	cd clients/rust && cargo doc --open

# ============== Combined Targets ==============

all-build: build rust-build

all-test: test rust-test

all-clean: clean rust-clean
