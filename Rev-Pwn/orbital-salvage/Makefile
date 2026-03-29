PROJECT := orbital-salvage
IMAGE := orbital-salvage:latest
HANDOUT_BIN := handout/orbital-salvage

.PHONY: build release strip handout clean docker-build docker-run

build:
	cargo build

release:
	RUSTFLAGS="-C target-cpu=native -C opt-level=z -C codegen-units=1 -C panic=abort -C strip=symbols -C strip=debuginfo -C link-arg=-s" \
		cargo build --release
	strip target/release/$(PROJECT)
	mkdir -p handout
	cp target/release/$(PROJECT) $(HANDOUT_BIN)

clean:
	cargo clean
	rm -f $(HANDOUT_BIN)

docker-build:
	docker build -t $(IMAGE) .

docker-run:
	docker run --rm -p 31337:31337 $(IMAGE)
