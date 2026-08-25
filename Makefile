# Copyright 2020 Ipalfish, Inc.
# Copyright 2022 PingCAP, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

GO := go
CARGO := cargo
GOBIN := $(shell pwd)/bin
VERSION ?= $(shell git describe --tags --dirty --always)
BRANCH ?= $(shell git rev-parse --abbrev-ref HEAD)
COMMIT ?= $(shell git describe --match=NeVeRmAtCh --always --abbrev=40 --dirty)
BUILD_TIME ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
DEBUG ?=
DOCKERPREFIX ?=
BUILD_TAGS ?=
LDFLAGS ?=
LDFLAGS += -X "github.com/pingcap/tiproxy/pkg/util/versioninfo.TiProxyVersion=$(VERSION)"
LDFLAGS += -X "github.com/pingcap/tiproxy/pkg/util/versioninfo.TiProxyGitBranch=$(BRANCH)"
LDFLAGS += -X "github.com/pingcap/tiproxy/pkg/util/versioninfo.TiProxyGitHash=$(COMMIT)"
LDFLAGS += -X "github.com/pingcap/tiproxy/pkg/util/versioninfo.TiProxyBuildTS=$(shell date -u '+%Y-%m-%d %H:%M:%S')"

BUILDFLAGS ?= -gcflags '$(GCFLAGS)' -ldflags '$(LDFLAGS)' -tags '$(BUILD_TAGS)'
ifneq ("$(DEBUG)", "")
	BUILDFLAGS += -race
endif
IMAGE_TAG ?= latest
EXECUTABLE_TARGETS := $(patsubst cmd/%,cmd_%,$(wildcard cmd/*))
RUST_MANIFEST := rust/Cargo.toml
RUST_TARGET ?= $(shell rustc -vV | sed -n 's/^host: //p')
RUST_BUILD_ENV := TIPROXY_VERSION=$(VERSION) TIPROXY_COMMIT=$(COMMIT) TIPROXY_BUILD_TIME=$(BUILD_TIME)
CARGO_AUDIT_VERSION := 0.22.2
CARGO_DENY_VERSION := 0.20.2
RUST_TOOL_ROOT ?= $(GOBIN)/rust-tools
RUST_TOOL_BIN := $(RUST_TOOL_ROOT)/bin

.PHONY: cmd_% test lint parity-drift parity-drift-weekly docker docker-release golangci-lint gocovmerge clean rust-build rust-test rust-doc-test rust-lint rust-release rust-install-tools rust-supply-chain rust-negative-tests dataplane-integration dataplane-integration-go dataplane-integration-self-test

default: cmd

dev: build lint test

cmd: $(EXECUTABLE_TARGETS)

cmd_%: OUTPUT=$(patsubst cmd_%,./bin/%,$@)
cmd_%: SOURCE=$(patsubst cmd_%,./cmd/%,$@)
cmd_%:
	$(GO) build $(BUILDFLAGS) -o $(OUTPUT) $(SOURCE)

golangci-lint:
	GOBIN=$(GOBIN) GOTOOLCHAIN=go1.25.12 $(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8

go-header:
	GOBIN=$(GOBIN) $(GO) install github.com/denis-tingaikin/go-header/cmd/go-header@latest

header: go-header
	NEW_GO_FILES=$(git diff --cached --diff-filter=A --name-only | grep -E '.*\.go')
	[ ! $(NEW_GO_FILES) ] || $(GOBIN)/go-header $(NEW_GO_FILES)

lint: golangci-lint tidy header
	cd lib && $(GOBIN)/golangci-lint run -c ../.golangci.yaml
	$(GOBIN)/golangci-lint run -c .golangci.yaml

gocovmerge:
	GOBIN=$(GOBIN) $(GO) install github.com/djshow832/gocovmerge@master

tidy:
	cd lib && $(GO) mod tidy
	$(GO) mod tidy

build:
	cd lib && $(GO) build ./...
	$(GO) build ./...

rust-build:
	$(RUST_BUILD_ENV) $(CARGO) build --locked --workspace --manifest-path $(RUST_MANIFEST)

rust-test:
	$(RUST_BUILD_ENV) $(CARGO) test --locked --workspace --manifest-path $(RUST_MANIFEST)

rust-doc-test:
	$(RUST_BUILD_ENV) $(CARGO) test --locked --workspace --doc --manifest-path $(RUST_MANIFEST)

rust-lint:
	$(CARGO) fmt --all --manifest-path $(RUST_MANIFEST) -- --check
	$(RUST_BUILD_ENV) $(CARGO) clippy --locked --workspace --all-targets --all-features --manifest-path $(RUST_MANIFEST) -- -D warnings

rust-release:
	$(RUST_BUILD_ENV) $(CARGO) build --locked --workspace --release --target $(RUST_TARGET) --manifest-path $(RUST_MANIFEST)

rust-install-tools:
	$(CARGO) install --locked --root $(RUST_TOOL_ROOT) cargo-audit --version $(CARGO_AUDIT_VERSION)
	$(CARGO) install --locked --root $(RUST_TOOL_ROOT) cargo-deny --version $(CARGO_DENY_VERSION)

rust-supply-chain:
	PATH=$(RUST_TOOL_BIN):$(PATH) rust/ci/check-supply-chain.sh

rust-negative-tests:
	PATH=$(RUST_TOOL_BIN):$(PATH) rust/ci/run-negative-tests.sh

# The default remains the intended Rust topology and fails its capability
# preflight until the real bridge/dataplane exists. The Go target is a truthful
# end-to-end baseline for the shared topology infrastructure.
dataplane-integration:
	./tests/dataplane/integration/run.sh --mode rust --variant all

dataplane-integration-go:
	./tests/dataplane/integration/run.sh --mode go --variant all

dataplane-integration-self-test:
	./tests/dataplane/integration/self-test.sh

metrics:
	$(GO) install github.com/google/go-jsonnet/cmd/jsonnet@latest
	[ -e "grafonnet-lib" ] || git clone --depth=1 https://github.com/grafana/grafonnet-lib
	JSONNET_PATH=grafonnet-lib jsonnet ./pkg/metrics/grafana/tiproxy_summary.jsonnet > ./pkg/metrics/grafana/tiproxy_summary.json

test: gocovmerge
	rm -f .cover.*
	$(GO) test -coverprofile=.cover.pkg ./...
	cd lib && $(GO) test -coverprofile=../.cover.lib ./...
	$(GOBIN)/gocovmerge .cover.* > coverage.dat
	$(GO) tool cover -func=coverage.dat -o .cover.func
	tail -1 .cover.func
	rm -f .cover.*
#	$(GO) tool cover -html=.cover -o .cover.html

PARITY_DRIFT_BASE ?= origin/main
PARITY_DRIFT_HEAD ?= HEAD

parity-drift:
	$(GO) run ./tests/dataplane/drift/cmd/drift -mode check -base "$(PARITY_DRIFT_BASE)" -head "$(PARITY_DRIFT_HEAD)"

parity-drift-weekly:
	tests/dataplane/drift/report-weekly.sh

clean:
	rm -rf bin dist grafonnet-lib rust/target

docker:
	docker build -t "$(DOCKERPREFIX)tiproxy:$(IMAGE_TAG)" --build-arg "GOPROXY=$(shell $(GO) env GOPROXY)" --build-arg "VERSION=$(VERSION)" --build-arg "COMMIT=$(COMMIT)" --build-arg "BRANCH=$(BRANCH)" -f docker/Dockerfile .

docker-release:
	docker buildx build --platform linux/amd64,linux/arm64 --push -t "$(DOCKERPREFIX)tiproxy:$(IMAGE_TAG)" --build-arg "GOPROXY=$(shell $(GO) env GOPROXY)" --build-arg "VERSION=$(VERSION)" --build-arg "COMMIT=$(COMMIT)" --build-arg "BRANCH=$(BRANCH)" -f docker/Dockerfile .
