build:
	cargo build
build-release:
	cargo build --release
test:
	cargo test
check:
	cargo check
lint:
	cargo clippy -- -D warnings

.PHONY: all run test check lint
