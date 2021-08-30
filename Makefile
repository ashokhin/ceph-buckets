GOPATH      := $(shell go env GOPATH)

BIN_DIR             ?= $(shell pwd)/bin
BIN_NAME            ?= $(shell go env GOEXE)

export APP_HOST        ?= $(shell hostname)
export APP_BRANCH      ?= $(shell git describe --all --contains --dirty HEAD)
export APP_REVISION    ?= $(shell git rev-parse HEAD)
export APP_ORIGIN      ?= $(shell git config --local --get remote.origin.url)
export APP_VERSION     := $(shell cat VERSION)
export APP_USER        := $(shell id -u --name)
export APP_BUILD_DATE  := $(shell date -u '+%Y-%m-%dT%H:%M:%S:%Z')

all: clean format vet build

clean:
	@echo ">> removing build artifacts"
	@rm -Rf $(BIN_DIR)
	@rm -Rf $(BIN_NAME)

format:
	@echo ">> formatting code"
	@go fmt ./...

vet:
	@echo ">> vetting code"
	@go vet $(pkgs)

build:
	@echo ">> building binary"
	@CGO_ENABLED=0 go build -v \
		-ldflags "-X 'main.appVersion=${APP_VERSION}' \
			-X main.appBranch=${APP_BRANCH} \
			-X main.appRevision=${APP_REVISION} \
			-X main.appBuildUser=${APP_USER}@${APP_HOST} \
			-X main.appBuildDate=${APP_BUILD_DATE} \
			-X main.AppOrigin=${APP_ORIGIN} \
		" \
		-o $(BIN_NAME) .