.PHONY: test build check-rules

test:
	go vet ./...
	go test ./...

build:
	go build -o build/trassa ./cmd/trassa
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o build/trassa-arm64 ./cmd/trassa

check-rules: build
	build/trassa check rules/rules.conf
