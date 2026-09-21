GO        ?= go
PKGS      := $(shell $(GO) list ./... | grep -v /ui/)
COVER_OUT := coverage.out

.PHONY: lint vuln test test-integration cover fuzz generate ui-build redaction-scan e2e compose-up compose-down

lint:
	$(GO) vet ./...
	staticcheck ./...
	gosec -quiet -exclude-generated -exclude-dir=ui ./...

vuln:
	../../scripts/vulncheck.sh

test:
	$(GO) test -race -count=1 ./...

test-integration:
	$(GO) test -race -count=1 -tags integration ./tests/integration/...

# Generated protobuf, SQL bindings (internal/store, */*db), wiring (internal/app,
# cmd) and test packages are exercised by the tagged integration suite and are
# excluded from the unit gate on purpose.
COVERPKG := $(shell $(GO) list ./... | grep -v -E '/api/|/internal/store$$|db$$|/internal/app$$|/valkeykv$$|/cmd/|/tests/|/ui' | paste -sd, -)

cover:
	$(GO) test -count=1 -coverprofile=$(COVER_OUT) -coverpkg=$(COVERPKG) $(PKGS)
	./scripts/coverage-gate.sh $(COVER_OUT)

fuzz:
	for f in FuzzCSR FuzzSPIFFEID FuzzBundle FuzzSSEFrame FuzzEnrollToken FuzzWebhookSig FuzzBackup; do \
	  $(GO) test -run xxx -fuzz=$$f -fuzztime=20s ./tests/fuzz/ || exit 1; done

generate:
	buf generate

ui-build:
	cd ui && npm ci && npm run build

redaction-scan:
	./scripts/redaction-scan.sh

e2e:
	cd ui && npx playwright test

compose-up:
	docker compose -p lcm -f deploy/compose.yaml up -d

compose-down:
	docker compose -p lcm -f deploy/compose.yaml down -v
