GOVERSION				:= $(shell go env GOVERSION)
GOARCH					:= $(shell go env GOARCH)
GOOS					:= $(shell go env GOOS)

BIN_DIR					?= $(shell pwd)/bin
BIN_NAME				?= $(shell go env GOEXE)

export APP_HOST			?= $(shell hostname)
export APP_BRANCH		?= $(shell git describe --all --contains --dirty HEAD)
export APP_REVISION		?= $(shell git rev-parse HEAD)
export APP_ORIGIN		?= $(shell git config --local --get remote.origin.url)
export APP_VERSION		:= $(shell basename ${APP_BRANCH})
export APP_USER			:= $(shell id -u --name)
export APP_BUILD_DATE	:= $(shell date -u '+%Y-%m-%dT%H:%M:%S,%N%:z')

all: clean format vet test build

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

test:
	@echo ">> testing code"
	@go test ./collector
	@go test .

build:
	@echo ">> building binary"
	@CGO_ENABLED=0 go build -v \
		-ldflags "-X 'main.appVersion=${APP_VERSION}, ${GOVERSION}, ${GOOS}/${GOARCH}' \
			-X main.appBranch=${APP_BRANCH} \
			-X main.appRevision=${APP_REVISION} \
			-X main.appBuildUser=${APP_USER}@${APP_HOST} \
			-X main.appBuildDate=${APP_BUILD_DATE} \
			-X 'main.appOrigin=${APP_ORIGIN}' \
		" \
		-o $(BIN_NAME) .
