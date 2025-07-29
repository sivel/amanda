APP=amanda
GIT_SHA=$(shell git rev-parse HEAD)$(shell git diff --quiet || echo +)
BUILD_DATE=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GO_VERSION=$(shell go version | awk '{print $$3}')

build:
	CGO_ENABLED=0 go build -ldflags "-X main.gitSHA=$(GIT_SHA) -X main.buildDate=$(BUILD_DATE) -X main.goVersion=$(GO_VERSION)" -o $(APP)

clean:
	rm -f $(APP)
