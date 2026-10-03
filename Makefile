.PHONY: test build check-rules

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
	go build -o build/trassa ./cmd/trassa
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o build/trassa-arm64 ./cmd/trassa

check-rules: build
	build/trassa check rules/rules.conf
