APP        := amanda
GOOS       := $(shell go env GOOS)
GOARCH     := $(shell go env GOARCH)
GIT_SHA    := $(shell git rev-parse HEAD)$(shell git diff --quiet || echo +)
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GO_VERSION := $(shell go version | awk '{print $$3}')

SRC        := $(shell find . -type f -name '*.go') go.mod go.sum index.html

.PHONY: build clean

$(APP): $(SRC)
	@mkdir -p build
ifneq ($(GOOS),linux)
	GOOS=linux GOARCH=$(GOARCH) CGO_ENABLED=0 go build -ldflags "-X main.gitSHA=$(GIT_SHA) -X main.buildDate=$(BUILD_DATE) -X main.goVersion=$(GO_VERSION)" -o "build/$(APP)_linux_$(GOARCH)"
endif
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build -ldflags "-X main.gitSHA=$(GIT_SHA) -X main.buildDate=$(BUILD_DATE) -X main.goVersion=$(GO_VERSION)" -o "build/$(APP)_$(GOOS)_$(GOARCH)"
	GOOS=$(GOOS) GOARCH=$(GOARCH) ln -sf "build/$(APP)_$(GOOS)_$(GOARCH)" $(APP)

build: $(APP)

clean:
	rm -rf build/
	unlink $(APP)
