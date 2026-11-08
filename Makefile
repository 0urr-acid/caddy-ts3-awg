CADDY_VERSION ?= v2.11.9
MODULE := github.com/0urr-acid/caddy-ts3-awg

.PHONY: build test vet verify xcaddy clean

build:
	@mkdir -p bin
	go build -trimpath -buildvcs=false -o bin/caddy ./cmd/caddy

test:
	go test -race ./...

vet:
	go vet ./...

verify:
	go mod verify

xcaddy:
	@mkdir -p bin
	xcaddy build $(CADDY_VERSION) --output bin/caddy --with $(MODULE)=.

clean:
	rm -rf bin
