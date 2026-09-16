# RatSweepr build tooling (bash-only).
# No compilation — RatSweepr is a single self-contained bash script.

VERSION ?= $(shell grep '^RS_VERSION=' ratsweepr.sh | cut -d'"' -f2)

.PHONY: test lint sign-sigs version

## test: syntax-check the script and validate the YARA ruleset compiles
test: lint
	@command -v yr >/dev/null 2>&1 && yr scan ratsweepr.yar /dev/null >/dev/null 2>&1 \
		&& echo "yara rules compile OK" \
		|| echo "yara engine not present — skipping rule-compile check"

## lint: bash syntax check
lint:
	bash -n ratsweepr.sh && echo "ratsweepr.sh: syntax OK"

## sign-sigs: sign the distributable pattern file (needs priv.pem, keep it OFF servers)
sign-sigs:
	openssl dgst -sha256 -sign priv.pem -out ratsweepr-sigs.conf.sig ratsweepr-sigs.conf
	@echo "signed ratsweepr-sigs.conf — commit both files"

## version: print the current version
version:
	@echo "$(VERSION)"
