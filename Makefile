# ====================================
# HELP
# ====================================

## help: show all available commands
.PHONY: help
help:
	@printf 'Usage:\n\n'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'
	@printf '\n'


# ====================================
# LOCAL DEVELOPMENT
# ====================================

## tidy: cleanup modfiles and modernize/format all .go files
.PHONY: tidy
tidy:
	go mod tidy -v
	go fix ./...
	go fmt ./...

## vet: run go vet across all packages
.PHONY: vet
vet:
	go vet ./...

## test: run all tests with the race detector
.PHONY: test
test:
	go test -race ./...

## cover: run tests and open the coverage report in a browser
.PHONY: cover
cover:
	go test -coverpkg=./... -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out


# ====================================
# RELEASE
# ====================================

## release: tag and push to publish the module (make release VERSION=v0.1.0)
.PHONY: release
release:
	@test -n "$(VERSION)" || { echo "VERSION is required, e.g. make release VERSION=v0.1.0"; exit 1; }
	go mod tidy
	go test -race ./...
	git tag -a $(VERSION) -m $(VERSION)
	git push origin $(VERSION)
