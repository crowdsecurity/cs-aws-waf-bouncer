# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get

GOOS ?= linux
GOARCH ?= amd64

# Current versioning information from env
BUILD_VERSION?="$(shell git describe --tags)"
BUILD_TIMESTAMP=$(shell date +%F"_"%T)
BUILD_TAG="$(shell git rev-parse HEAD)"

export LD_OPTS=-ldflags "-s -w -X github.com/crowdsecurity/cs-aws-waf-bouncer/version.Version=$(BUILD_VERSION) \
-X github.com/crowdsecurity/cs-aws-waf-bouncer/version.BuildDate=$(BUILD_TIMESTAMP) \
-X github.com/crowdsecurity/cs-aws-waf-bouncer/version.Tag=$(BUILD_TAG)"
PREFIX?="/"
BINARY_NAME=crowdsec-aws-waf-bouncer

RELDIR = "crowdsec-aws-waf-bouncer-${BUILD_VERSION}"

all: clean build

static: clean
	$(GOBUILD) $(LD_OPTS) -o $(BINARY_NAME) -v -a -tags netgo -ldflags '-w -extldflags "-static"'

build: goversion clean
	$(GOBUILD) $(LD_OPTS) -o $(BINARY_NAME) -v

clean:
	@rm -f $(BINARY_NAME)
	@rm -rf ${RELDIR}
	@rm -f crowdsec-aws-waf-bouncer-*.tgz || ""

.PHONY: release
release: build
	@if [ -z ${BUILD_VERSION} ] ; then BUILD_VERSION="local" ; fi
	@if [ -d $(RELDIR) ]; then echo "$(RELDIR) already exists, clean" ;  exit 1 ; fi
	@echo Building Release to dir $(RELDIR)
	@mkdir $(RELDIR)/
	@cp $(BINARY_NAME) $(RELDIR)/
	@cp -R ./config $(RELDIR)/
	@cp ./scripts/install.sh $(RELDIR)/
	@cp ./scripts/uninstall.sh $(RELDIR)/
	@cp ./scripts/upgrade.sh $(RELDIR)/
	@chmod +x $(RELDIR)/install.sh
	@chmod +x $(RELDIR)/uninstall.sh
	@chmod +x $(RELDIR)/upgrade.sh
	@tar cvzf crowdsec-aws-waf-bouncer-$(GOOS)-$(GOARCH).tgz $(RELDIR)

release_static: static
	@if [ -z ${BUILD_VERSION} ] ; then BUILD_VERSION="local" ; fi
	@if [ -d $(RELDIR) ]; then echo "$(RELDIR) already exists, clean" ;  exit 1 ; fi
	@echo Building Release to dir $(RELDIR)
	@mkdir $(RELDIR)/
	@cp $(BINARY_NAME) $(RELDIR)/
	@cp -R ./config $(RELDIR)/
	@cp ./scripts/install.sh $(RELDIR)/
	@cp ./scripts/uninstall.sh $(RELDIR)/
	@cp ./scripts/upgrade.sh $(RELDIR)/
	@chmod +x $(RELDIR)/install.sh
	@chmod +x $(RELDIR)/uninstall.sh
	@chmod +x $(RELDIR)/upgrade.sh
	@tar cvzf crowdsec-aws-waf-bouncer-$(GOOS)-$(GOARCH)-static.tgz $(RELDIR)

include mk/goversion.mk
