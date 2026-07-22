# RatSweepr build tooling.
# Requires Go 1.22+ (https://go.dev/dl or `apt install golang-go`).

VERSION ?= $(shell grep 'appVersion = ' core.go | cut -d'"' -f2)
LDFLAGS  = -s -w
DIST     = dist

.PHONY: build run test release checksums clean tidy

## build: compile for the current machine -> ./ratsweepr
build:
	go build -o ratsweepr .

## run: build and launch the TUI (from a WordPress root!)
run: build
	./ratsweepr

## test: vet + build all packages
test:
	go vet ./...
	go build ./...

## release: cross-compile static binaries for typical hosts -> dist/
release: clean
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(DIST)/ratsweepr-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux  GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(DIST)/ratsweepr-linux-arm64 .
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(DIST)/ratsweepr-darwin-arm64 .
	$(MAKE) checksums
	@echo "release $(VERSION) built in $(DIST)/"

## checksums: dist/checksums.txt for install.sh verification
checksums:
	cd $(DIST) && sha256sum ratsweepr-* > checksums.txt

## sign-sigs: sign the pattern file (needs priv.pem, keep it OFF servers)
sign-sigs:
	openssl dgst -sha256 -sign priv.pem -out ratsweepr-sigs.conf.sig ratsweepr-sigs.conf
	@echo "signed ratsweepr-sigs.conf — commit both files"

## tidy: normalize modules (safe to run after editing imports)
tidy:
	go mod tidy

clean:
	rm -rf $(DIST) ratsweepr
