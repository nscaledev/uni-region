# Application version encoded in all the binaries.
VERSION = 0.0.0

# Base go module name.
MODULE := $(shell cat go.mod | grep -m1 module | awk '{print $$2}')

# Git revision.
REVISION := $(shell git rev-parse HEAD)

# Commands to build, the first lot are architecture agnostic and will be built
# for your host's architecture.  The latter are going to run in Kubernetes, so
# want to be amd64.
CONTROLLERS = \
  unikorn-region-controller \
  unikorn-region-project-consumer \
  unikorn-identity-controller \
  unikorn-network-controller \
  unikorn-security-group-controller \
  unikorn-server-controller \
  unikorn-region-monitor \
  unikorn-file-storage-controller

# Release will do cross compliation of all images for the 'all' target.
# Note we aren't fucking about with docker here because that opens up a
# whole can of worms to do with caching modules and pisses on performance,
# primarily making me rage.  For image creation, this, by necessity,
# REQUIRES multiarch images to be pushed to a remote registry because
# Docker apparently cannot support this after some 3 years...  So don't
# run that target locally when compiling in release mode.
ifdef RELEASE
CONTROLLER_ARCH := amd64 arm64
BUILDX_OUTPUT := --push
else
CONTROLLER_ARCH := $(shell go env GOARCH)
BUILDX_OUTPUT := --load
endif

# Calculate the platform list to pass to docker buildx.
BUILDX_PLATFORMS := $(shell echo $(patsubst %,linux/%,$(CONTROLLER_ARCH)) | sed 's/ /,/g')

# Some constants to describe the repository.
BINDIR = bin
CMDDIR = cmd
SRCDIR = src
GENDIR = generated
CRDDIR = charts/region/crds

# Where to install things.
PREFIX = $(HOME)/bin

# List of binaries to build.
CONTROLLER_BINARIES := $(foreach arch,$(CONTROLLER_ARCH),$(foreach ctrl,$(CONTROLLERS),$(BINDIR)/$(arch)-linux-gnu/$(ctrl)))

# List of sources to trigger a build.
# TODO: Bazel may be quicker, but it's a massive hog, and a pain in the arse.
SOURCES := $(shell find . -type f -name *.go) go.mod go.sum

# Source files defining custom resource APIs
APISRC = $(shell find pkg/apis -name [^z]*.go -type f)

# Some bits about go.
GOPATH := $(shell go env GOPATH)
GOBIN := $(if $(shell go env GOBIN),$(shell go env GOBIN),$(GOPATH)/bin)

# Common linker flags.
FLAGS=-trimpath -ldflags '-X $(MODULE)/pkg/constants.Version=$(VERSION) -X $(MODULE)/pkg/constants.Revision=$(REVISION)'

# Defines the linter version.
LINT_VERSION=v2.1.5

# Defines the version of the CRD generation tools to use.
CONTROLLER_TOOLS_VERSION=v0.17.3

# Defines the version of code generator tools to use.
# This should be kept in sync with the Kubenetes library versions defined in go.mod.
CODEGEN_VERSION := $(shell grep k8s.io/apimachinery go.mod | awk '{ print $$2; }')

OPENAPI_CODEGEN_VERSION=v2.4.1
OPENAPI_CODEGEN_FLAGS=-package openapi -config pkg/openapi/config.yaml
OPENAPI_SCHEMA=pkg/openapi/server.spec.yaml
OPENAPI_FILES = \
	pkg/openapi/types.go \
	pkg/openapi/schema.go \
	pkg/openapi/client.go \
	pkg/openapi/router.go

MOCKGEN_VERSION=v0.3.0

# This is the base directory to generate kubernetes API primitives from e.g.
# clients and CRDs.
GENAPIBASE = github.com/unikorn-cloud/region/pkg/apis/unikorn/v1alpha1

# These are generic arguments that need to be passed to client generation.
GENARGS = --go-header-file hack/boilerplate.go.txt

# This defines how docker containers are tagged.
DOCKER_ORG = ghcr.io/nscaledev

# Main target, builds all binaries.
.PHONY: all
all: $(CONTROLLER_BINARIES) $(CRDDIR)

# Create a binary output directory, this should be an order-only prerequisite.
$(BINDIR) $(BINDIR)/amd64-linux-gnu $(BINDIR)/arm64-linux-gnu:
	mkdir -p $@

$(BINDIR)/amd64-linux-gnu/%: $(SOURCES) $(GENDIR) $(OPENAPI_FILES) | $(BINDIR)/amd64-linux-gnu
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(FLAGS) -o $@ $(CMDDIR)/$*/main.go

$(BINDIR)/arm64-linux-gnu/%: $(SOURCES) $(GENDIR) $(OPENAPI_FILES) | $(BINDIR)/arm64-linux-gnu
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(FLAGS) -o $@ $(CMDDIR)/$*/main.go

# TODO: we may wamt to consider porting the rest of the CRD and client generation
# stuff over... that said, we don't need the clients really do we, controller-runtime
# does all the magic for us.
.PHONY: generate
generate:
	@go install go.uber.org/mock/mockgen@$(MOCKGEN_VERSION)
	go generate ./...

# Create container images.  Use buildkit here, as it's the future, and it does
# good things, like per file .dockerignores and all that jazz.
.PHONY: images
images: $(CONTROLLER_BINARIES)
	if [ -n "$(RELEASE)" ]; then docker buildx create --name unikorn --use; fi
	for image in ${CONTROLLERS}; do docker buildx build --platform $(BUILDX_PLATFORMS) $(BUILDX_OUTPUT) -f docker/$${image}/Dockerfile -t ${DOCKER_ORG}/$${image}:${VERSION} .; done;
	if [ -n "$(RELEASE)" ]; then docker buildx rm unikorn; fi

# Purely lazy command that builds and pushes to docker hub.
.PHONY: images-push
images-push: images
	for image in ${CONTROLLERS}; do docker push ${DOCKER_ORG}/$${image}:${VERSION}; done

.PHONY: images-kind-load
images-kind-load: images
	for image in ${CONTROLLERS}; do kind load docker-image ${DOCKER_ORG}/$${image}:${VERSION}; done

.PHONY: test-unit
test-unit:
	go test -coverpkg ./... -coverprofile cover.out $(shell go list ./... | grep -v /test/api | grep -v /test/contracts)
	go tool cover -html cover.out -o cover.html

# Build a binary and install it.
$(PREFIX)/%: $(BINDIR)/%
	install -m 750 $< $@

# Create any CRDs defined into the target directory.
$(CRDDIR): $(APISRC)
	@mkdir -p $@
	@go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)
	$(GOBIN)/controller-gen crd:crdVersions=v1 paths=./pkg/apis/unikorn/... output:dir=$@
	@touch $(CRDDIR)

# Generate a clientset to interact with our custom resources.
$(GENDIR): $(APISRC)
	@go install k8s.io/code-generator/cmd/deepcopy-gen@$(CODEGEN_VERSION)
	$(GOBIN)/deepcopy-gen --output-file zz_generated.deepcopy.go $(GENARGS) $(GENAPIBASE)
	@touch $@

# Generate the server schema, types and router boilerplate.
pkg/openapi/types.go: $(OPENAPI_SCHEMA)
	@go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@$(OPENAPI_CODEGEN_VERSION)
	oapi-codegen -generate types $(OPENAPI_CODEGEN_FLAGS) -o $@ $<

pkg/openapi/schema.go: $(OPENAPI_SCHEMA)
	@go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@$(OPENAPI_CODEGEN_VERSION)
	oapi-codegen -generate spec $(OPENAPI_CODEGEN_FLAGS) -o $@ $<

pkg/openapi/client.go: $(OPENAPI_SCHEMA)
	@go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@$(OPENAPI_CODEGEN_VERSION)
	oapi-codegen -generate client $(OPENAPI_CODEGEN_FLAGS) -o $@ $<

pkg/openapi/router.go: $(OPENAPI_SCHEMA)
	@go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@$(OPENAPI_CODEGEN_VERSION)
	oapi-codegen -generate chi-server $(OPENAPI_CODEGEN_FLAGS) -o $@ $<

# When checking out, the files timestamps are pretty much random, and make cause
# spurious rebuilds of generated content.  Call this to prevent that.
.PHONY: touch
touch:
	touch $(CRDDIR) $(GENDIR) pkg/apis/unikorn/v1alpha1/zz_generated.deepcopy.go

# Perform linting.
# This must pass or you will be denied by CI.
.PHOMY: lint
lint: $(GENDIR)
	@go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(LINT_VERSION)
	$(GOBIN)/golangci-lint run --timeout=10m ./...
	helm lint --strict charts/region

# Validate the server OpenAPI schema is legit.
.PHONY: validate
validate: $(OPENAPI_FILES)
	go run ./hack/validate_openapi

# Validate the docs can be generated without fail.
.PHONY: validate-docs
validate-docs: $(OPENAPI_FILES)
	go run github.com/unikorn-cloud/core/hack/docs --dry-run

# Perform license checking.
# This must pass or you will be denied by CI.
.PHONY: license
license:
	go run github.com/unikorn-cloud/core/hack/check_license

# API test targets
.PHONY: test-api
test-api: test-api-setup
	cd test/api/suites && ginkgo run -v --show-node-events --json-report=test-results.json --junit-report=junit.xml

.PHONY: test-api-verbose
test-api-verbose: test-api-setup
	cd test/api/suites && ginkgo run -v --show-node-events --json-report=test-results.json --junit-report=junit.xml

.PHONY: test-api-focus
test-api-focus: test-api-setup
	cd test/api/suites && LOG_REQUESTS=true LOG_RESPONSES=true ginkgo run -v --focus="$(FOCUS)" --json-report=test-results.json --junit-report=junit.xml

.PHONY: test-api-suite
test-api-suite: test-api-setup
	cd test/api/suites && ginkgo run $(SUITE) --json-report=test-results.json --junit-report=junit.xml

.PHONY: test-api-parallel
test-api-parallel: test-api-setup
	cd test/api/suites && ginkgo run --procs=4 --json-report=test-results.json --junit-report=junit.xml

.PHONY: test-api-ci
test-api-ci: test-api-setup
	cd test/api/suites && ginkgo run --randomize-all --randomize-suites --race --json-report=test-results.json --junit-report=junit.xml --output-interceptor-mode=none

.PHONY: test-api-setup
test-api-setup:
	@go install github.com/onsi/ginkgo/v2/ginkgo@latest
	@go install github.com/onsi/gomega/...@latest

# Clean test artifacts
.PHONY: test-api-clean
test-api-clean:
	@rm -f test/api/suites/test-results.json test/api/suites/junit.xml

# Pact Broker Configuration
PACT_BROKER_URL ?= http://localhost:9292
PACT_BROKER_USERNAME ?= pact
PACT_BROKER_PASSWORD ?= pact
PROVIDER_VERSION ?= $(REVISION)

# Run provider contract verification tests
.PHONY: test-contracts-provider
test-contracts-provider:
	@echo "Running provider contract verification tests..."
	CGO_LDFLAGS="-L$(HOME)/Library/pact -Wl,-rpath,$(HOME)/Library/pact" \
	DYLD_LIBRARY_PATH="$(HOME)/Library/pact:$$DYLD_LIBRARY_PATH" \
	KUBECONFIG="$(HOME)/.kube/config" \
	PACT_BROKER_URL="$(PACT_BROKER_URL)" \
	PACT_BROKER_USERNAME="$(PACT_BROKER_USERNAME)" \
	PACT_BROKER_PASSWORD="$(PACT_BROKER_PASSWORD)" \
	PROVIDER_VERSION="$(PROVIDER_VERSION)" \
	go test ./test/contracts/provider/... -v -count=1

# Run provider verification with verbose output
.PHONY: test-contracts-provider-verbose
test-contracts-provider-verbose:
	@echo "Running provider contract verification with verbose output..."
	CGO_LDFLAGS="-L$(HOME)/Library/pact -Wl,-rpath,$(HOME)/Library/pact" \
	DYLD_LIBRARY_PATH="$(HOME)/Library/pact:$$DYLD_LIBRARY_PATH" \
	KUBECONFIG="$(HOME)/.kube/config" \
	PACT_BROKER_URL="$(PACT_BROKER_URL)" \
	PACT_BROKER_USERNAME="$(PACT_BROKER_USERNAME)" \
	PACT_BROKER_PASSWORD="$(PACT_BROKER_PASSWORD)" \
	PROVIDER_VERSION="$(PROVIDER_VERSION)" \
	VERBOSE=true \
	go test ./test/contracts/provider/... -v -count=1

# Run provider verification from local pact file
.PHONY: test-contracts-provider-local
test-contracts-provider-local:
	@echo "Running provider verification from local pact file..."
	@if [ -z "$(PACT_FILE)" ]; then \
		echo "Error: PACT_FILE environment variable must be set"; \
		echo "Usage: make test-contracts-provider-local PACT_FILE=/path/to/pact.json"; \
		exit 1; \
	fi
	CGO_LDFLAGS="-L$(HOME)/Library/pact -Wl,-rpath,$(HOME)/Library/pact" \
	DYLD_LIBRARY_PATH="$(HOME)/Library/pact:$$DYLD_LIBRARY_PATH" \
	KUBECONFIG="$(HOME)/.kube/config" \
	PACT_FILE="$(PACT_FILE)" \
	PROVIDER_VERSION="$(PROVIDER_VERSION)" \
	go test ./test/contracts/provider/... -v -count=1

# Publish verification results (for CI)
.PHONY: test-contracts-provider-ci
test-contracts-provider-ci:
	@echo "Running provider verification and publishing results..."
	CGO_LDFLAGS="-L$(HOME)/Library/pact -Wl,-rpath,$(HOME)/Library/pact" \
	DYLD_LIBRARY_PATH="$(HOME)/Library/pact:$$DYLD_LIBRARY_PATH" \
	KUBECONFIG="$(HOME)/.kube/config" \
	PACT_BROKER_URL="$(PACT_BROKER_URL)" \
	PACT_BROKER_USERNAME="$(PACT_BROKER_USERNAME)" \
	PACT_BROKER_PASSWORD="$(PACT_BROKER_PASSWORD)" \
	PROVIDER_VERSION="$(PROVIDER_VERSION)" \
	PUBLISH_VERIFICATION=true \
	go test ./test/contracts/provider/... -v -count=1

# Publish provider verification results to Pact Broker
.PHONY: publish-contracts-provider
publish-contracts-provider:
	@echo "Running provider verification and publishing results to Pact Broker..."
	@echo "Provider Version: $(PROVIDER_VERSION)"
	@echo "Pact Broker URL: $(PACT_BROKER_URL)"
	CGO_LDFLAGS="-L$(HOME)/Library/pact -Wl,-rpath,$(HOME)/Library/pact" \
	DYLD_LIBRARY_PATH="$(HOME)/Library/pact:$$DYLD_LIBRARY_PATH" \
	KUBECONFIG="$(HOME)/.kube/config" \
	PACT_BROKER_URL="$(PACT_BROKER_URL)" \
	PACT_BROKER_USERNAME="$(PACT_BROKER_USERNAME)" \
	PACT_BROKER_PASSWORD="$(PACT_BROKER_PASSWORD)" \
	PROVIDER_VERSION="$(PROVIDER_VERSION)" \
	PUBLISH_VERIFICATION=true \
	go test ./test/contracts/provider/... -v -count=1

# Clean contract test artifacts
.PHONY: test-contracts-clean
test-contracts-clean:
	@rm -f test/contracts/provider/**/*.log
	@rm -f test/contracts/provider/**/*.out
	@rm -f test/contracts/provider/**/*.test
