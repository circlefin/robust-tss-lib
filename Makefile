# Portions Copyright (c) 2023, Circle Internet Financial, LTD.  All rights reserved
# Circle contributions are licensed under the Apache 2.0 License.
#
# SPDX-License-Identifier: Apache-2.0 AND MIT


MODULE = github.com/bnb-chain/tss-lib/v2
PACKAGES = $(shell go list ./... | grep -v '/vendor/')

all: protob test

########################################
### Protocol Buffers

protob:
	@echo "--> Building Protocol Buffers"
	@for protocol in message signature ecdsa-cggplus ecdsa-keygen ecdsa-signing ecdsa-resharing eddsa-keygen eddsa-signing eddsa-resharing; do \
		echo "Generating $$protocol.pb.go" ; \
		protoc --go_out=. ./protob/$$protocol.proto ; \
	done

build: protob
	go fmt ./...

########################################
### Testing

clean_test:
	@echo "--> Cleaning test cache"
	go clean -testcache

test_unit:
	@echo "--> Running Unit Tests"
	@echo "!!! WARNING: This will take a long time :)"
	go clean -testcache
	go test -timeout 60m $(PACKAGES)

test_unit_race:
	@echo "--> Running Unit Tests (with Race Detection)"
	@echo "!!! WARNING: This will take a long time :)"
	go clean -testcache
	go test -timeout 60m -race $(PACKAGES)

test:
	make test_unit

########################################
### Pre Commit

pre_commit: build test

########################################

# To avoid unintended conflicts with file names, always add to .PHONY
# # unless there is a reason not to.
# # https://www.gnu.org/software/make/manual/html_node/Phony-Targets.html
.PHONY: protob build test_unit test_unit_race test

