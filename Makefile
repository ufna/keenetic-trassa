.PHONY: test build check-rules dist package-test shellcheck

# The version the builds carry: the release tag without its "v", or the commit between releases.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//')

# test also builds for the routers' processors: ARM64, and MIPS of both byte orders (the MIPS
# builds compile but have not run on a real router).
test:
	go vet ./...
	go test ./...
	go build -o /dev/null ./cmd/trassa
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o /dev/null ./cmd/trassa
	GOOS=linux GOARCH=mipsle GOMIPS=softfloat CGO_ENABLED=0 go build -o /dev/null ./cmd/trassa
	GOOS=linux GOARCH=mips GOMIPS=softfloat CGO_ENABLED=0 go build -o /dev/null ./cmd/trassa

build:
	go build -ldflags "-X main.version=$(VERSION)" -o build/trassa ./cmd/trassa
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o build/trassa-arm64 ./cmd/trassa

check-rules: build
	build/trassa check rules/rules.conf

# dist: the release files in dist/ (opkg packages, install.sh, SHA256SUMS). The version is the
# release's, e.g. make dist VERSION=0.1.0.
dist:
	tools/package.sh $(VERSION) dist

# package-test: the release files without a router: package layout, Entware's opkg in a container,
# install.sh under busybox ash. Needs Docker.
package-test:
	tools/package-test.sh

# shellcheck: the shell scripts; the router's own ones as POSIX sh, since busybox ash runs them there.
shellcheck:
	shellcheck -S warning -s sh deploy/S99trassa deploy/50-trassa-*.sh deploy/install.sh deploy/opkg/postinst deploy/opkg/prerm tools/package-test/arch.sh
	shellcheck -S warning tools/*.sh tools/package-test/entware.sh
