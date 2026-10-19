# lint: run all linters against the full tree (mirrors CI super-linter checks).
#
# Requires: golangci-lint, shellcheck, yamllint, npx (markdownlint-cli2),
#           python3, zizmor.  Install zizmor/yamllint: pip install yamllint zizmor
lint:
	@echo "[lint] Go — root module"
	golangci-lint run ./...
	@echo "[lint] Go — test/parity/suite"
	cd test/parity/suite && golangci-lint run ./...
	@echo "[lint] Go — test/integration/testify"
	cd test/integration/testify && golangci-lint run --build-tags integration ./...
	@echo "[lint] Go — test/integration/pipstub"
	cd test/integration/pipstub && golangci-lint run ./...
	@echo "[lint] Shell"
	find . -name '*.sh' -not -path './.git/*' | xargs shellcheck --severity=error
	@echo "[lint] YAML"
	find . \( -name '*.yml' -o -name '*.yaml' \) \
	    -not -path './.git/*' \
	    -not -path './node_modules/*' \
	    -not -path './helm-templates/*/templates/*.yaml' \
	  | xargs $${YAMLLINT_BIN:-$${HOME}/.local/bin/yamllint} -c .github/linters/.yaml-lint.yml
	@echo "[lint] Markdown"
	npx --yes markdownlint-cli2 --config .github/linters/.markdown-lint.yml "**/*.md" "#node_modules" \
	    "#apm_modules" "#.agents" "#.claude/rules" "#.claude/skills" "#.cursor/rules"
	@echo "[lint] GitHub Actions (zizmor)"
	$${ZIZMOR_BIN:-$${HOME}/.local/bin/zizmor} --config .github/linters/zizmor.yaml \
	    .github/workflows/*.yaml .github/workflows/*.yml
	@echo "[lint] All checks passed."

# install-hooks: point git at the bundled hooks directory.
install-hooks:
	git config core.hooksPath .githooks
	@echo "[install-hooks] pre-commit hook active (core.hooksPath=.githooks)"

# ── kind end-to-end ──────────────────────────────────────────────────────────
# Install the chart on a kind cluster and run the runtime suite against it.
# `make e2e` runs every step; CI calls the same targets one by one. See
# test/k8s/README.md.
KIND_CLUSTER ?= authz-e2e
E2E_NAMESPACE ?= authz-e2e
E2E_ARTIFACTS ?= test/artifacts/kind
E2E_KUBECTL := kubectl --context kind-$(KIND_CLUSTER) -n $(E2E_NAMESPACE)
E2E_HELM := helm --kube-context kind-$(KIND_CLUSTER) -n $(E2E_NAMESPACE)
# Extra arguments for every chart install, the test stand's included, for
# example E2E_HELM_ARGS='--set IMAGE_PULL_POLICY=Never'.
E2E_HELM_ARGS ?=
# Where the suites send their requests: the chart's Service, which fronts the
# agent Pod.
E2E_BASE_URL ?= http://authz-agent:8080
PARITY_AC_BASE_URL ?= http://authz-agent:8080
E2E_IMAGES := authz-agent authz-policy-admin pip-stub authz-runtime-suite \
              authz-parity-suite
TEST_STAND_CHART := helm-templates/authz-test-stand

e2e: e2e-cluster e2e-images e2e-harness e2e-install e2e-suite

e2e-cluster:
	kind get clusters | grep -qx $(KIND_CLUSTER) || kind create cluster --name $(KIND_CLUSTER) --wait 2m

# The images the charts reference as local/<name>:ci. Keycloak is the public
# image and is not built here.
e2e-images:
	docker build -t local/authz-agent:ci               -f build/authz-agent/Dockerfile .
	docker build -t local/authz-policy-admin:ci        -f build/authz-policy-admin/Dockerfile .
	docker build -t local/pip-stub:ci                  -f test/integration/pipstub/Dockerfile test/integration/pipstub
	docker build -t local/authz-runtime-suite:ci       -f test/integration/testify/Dockerfile .
	docker build -t local/authz-parity-suite:ci        -f test/parity/suite/Dockerfile test/parity/suite
	kind load docker-image --name $(KIND_CLUSTER) $(addprefix local/,$(addsuffix :ci,$(E2E_IMAGES)))

# The realm and stub files the test-stand chart reads from files/: the realms
# of test/k8s/authn/ and test/k8s/parity/idp-seed/, the users of
# test/parity/suite/testdata/realm/, and the pip-stub rule files. The transfer
# image generates the same files in the same Dockerfile stage.
test-stand-files:
	rm -rf $(TEST_STAND_CHART)/files
	docker build --target chart-files --output type=local,dest=$(TEST_STAND_CHART)/files -f build/authz-agent-transfer/Dockerfile .

# The test stand of test/k8s/test-stand-values.yaml: Keycloak with the realms
# of test/k8s/authn/, the two stubs, the M2M client-credentials Secret the
# chart expects the platform to provision, and the runtime suite Job, which
# e2e-suite runs.
e2e-harness: test-stand-files
	$(E2E_HELM) upgrade --install authz-test-stand $(TEST_STAND_CHART) --create-namespace -f test/k8s/test-stand-values.yaml --set suite.env.BASE_URL=$(E2E_BASE_URL) --wait --timeout 10m $(E2E_HELM_ARGS)

# The stub first: the agent reports Ready only once it has pulled its policies,
# so its --wait would run out with no policy source to pull from.
e2e-install:
	$(E2E_HELM) upgrade --install authz-policy-admin helm-templates/authz-policy-admin -f test/k8s/policy-admin-values.yaml --wait --timeout 5m $(E2E_HELM_ARGS)
	$(E2E_HELM) upgrade --install authz-agent helm-templates/authz-agent -f test/k8s/values.yaml --wait --timeout 5m $(E2E_HELM_ARGS)

# `helm test` runs the suite Job of the test stand and exits with its outcome.
# It prints the log only at the end, so the log is streamed while it runs.
# `kubectl logs -f` fails at once while the container is still being created,
# so the loop polls for up to three minutes until the log can be read.
# $(1) is kubectl, $(2) is helm, $(3) is the Job name, $(4) is how long helm
# waits for the Job, no shorter than its activeDeadlineSeconds.
define run-suite
$(1) delete job $(3) --ignore-not-found --wait
$(2) test authz-test-stand --timeout $(4) & helm_pid=$$!; \
	$(1) wait --for=create job/$(3) --timeout=2m \
	&& for i in $$(seq 90); do $(1) logs job/$(3) >/dev/null 2>&1 && break; sleep 2; done; \
	$(1) logs -f job/$(3); \
	wait $$helm_pid
endef

e2e-suite:
	$(call run-suite,$(E2E_KUBECTL),$(E2E_HELM),runtime-suite,15m)

# `make e2e-images` rebuilds the local images under the same tags, and a
# running Pod keeps the old content: the kubelet never re-reads a tag it
# already has. Restart every Deployment that runs a local image and wait until
# it is Ready again, so the next `e2e-suite` tests the new build. Keycloak runs
# the public image; `make e2e-harness` restarts it when a realm file changes.
E2E_LOCAL_DEPLOYMENTS := authz-agent authz-policy-admin pip-stub entitlements-mock
e2e-restart:
	$(E2E_KUBECTL) rollout restart $(addprefix deploy/,$(E2E_LOCAL_DEPLOYMENTS))
	for d in $(E2E_LOCAL_DEPLOYMENTS); do $(E2E_KUBECTL) rollout status deploy/$$d --timeout=3m || exit 1; done

# Everything needed to read a failed run: every container log on the node,
# the namespace events, and the decision logs downloaded from the agent.
e2e-logs:
	mkdir -p $(E2E_ARTIFACTS)
	kind export logs --name $(KIND_CLUSTER) $(E2E_ARTIFACTS)/cluster
	$(E2E_KUBECTL) get events --sort-by=.lastTimestamp > $(E2E_ARTIFACTS)/events.txt
	-$(E2E_KUBECTL) exec deploy/pip-stub -- wget -qO- http://authz-agent:8080/internal/v1/decision-logs > $(E2E_ARTIFACTS)/decision-logs.jsonl

e2e-down:
	kind delete cluster --name $(KIND_CLUSTER)

# ── parity replay on kind ────────────────────────────────────────────────────
# The parity suite (test/parity) against the chart, in its own namespace so its
# Keycloak realms and Service names match the Compose parity stack. Shares the
# cluster and the images with the e2e targets above.
PARITY_NAMESPACE ?= authz-parity
PARITY_KUBECTL := kubectl --context kind-$(KIND_CLUSTER) -n $(PARITY_NAMESPACE)
PARITY_HELM := helm --kube-context kind-$(KIND_CLUSTER) -n $(PARITY_NAMESPACE)

parity: e2e-cluster e2e-images parity-harness parity-install parity-suite

# The test stand of test/k8s/parity/test-stand-values.yaml: Keycloak with the
# realms of test/k8s/parity/idp-seed/ and the users of
# test/parity/suite/testdata/realm/, pip-mock with the request-args rule set,
# entitlements-mock, user-management-mock, the M2M client-credentials Secret
# for the parity-m2m client of the cloud-common realm, and the parity suite
# Job, which parity-suite runs.
parity-harness: test-stand-files
	$(PARITY_HELM) upgrade --install authz-test-stand $(TEST_STAND_CHART) --create-namespace -f test/k8s/parity/test-stand-values.yaml --set suite.env.PARITY_AC_BASE_URL=$(PARITY_AC_BASE_URL) --wait --timeout 10m $(E2E_HELM_ARGS)

# The stub first, as in e2e-install.
parity-install:
	$(PARITY_HELM) upgrade --install authz-policy-admin helm-templates/authz-policy-admin -f test/k8s/parity/policy-admin-values.yaml --wait --timeout 5m $(E2E_HELM_ARGS)
	$(PARITY_HELM) upgrade --install authz-agent helm-templates/authz-agent -f test/k8s/parity/values.yaml --wait --timeout 5m $(E2E_HELM_ARGS)

parity-suite:
	$(call run-suite,$(PARITY_KUBECTL),$(PARITY_HELM),parity-suite,5h30m)

# The parity counterpart of e2e-restart, for the same reason.
PARITY_LOCAL_DEPLOYMENTS := authz-agent authz-policy-admin pip-mock entitlements-mock user-management-mock
parity-restart:
	$(PARITY_KUBECTL) rollout restart $(addprefix deploy/,$(PARITY_LOCAL_DEPLOYMENTS))
	for d in $(PARITY_LOCAL_DEPLOYMENTS); do $(PARITY_KUBECTL) rollout status deploy/$$d --timeout=3m || exit 1; done

parity-logs:
	mkdir -p $(E2E_ARTIFACTS)/parity
	kind export logs --name $(KIND_CLUSTER) $(E2E_ARTIFACTS)/parity/cluster
	$(PARITY_KUBECTL) get events --sort-by=.lastTimestamp > $(E2E_ARTIFACTS)/parity/events.txt
	-$(PARITY_KUBECTL) exec deploy/pip-mock -- wget -qO- http://authz-agent:8080/internal/v1/decision-logs > $(E2E_ARTIFACTS)/parity/decision-logs.jsonl

.PHONY: lint install-hooks e2e e2e-cluster e2e-images test-stand-files e2e-harness e2e-install e2e-suite e2e-restart e2e-logs e2e-down parity parity-harness parity-install parity-suite parity-restart parity-logs
