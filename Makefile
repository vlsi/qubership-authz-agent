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
# Extra arguments for both chart installs, for example
# E2E_HELM_ARGS='--set IMAGE_PULL_POLICY=Never'.
E2E_HELM_ARGS ?=
# Where the suites send their requests: the chart's Service, which fronts the
# agent Pod.
E2E_BASE_URL ?= http://authz-agent:8080
PARITY_AC_BASE_URL ?= http://authz-agent:8080
E2E_AUTHN := test/k8s/authn
E2E_IMAGES := authz-agent authz-policy-admin pip-stub authz-runtime-suite \
              authz-parity-suite authz-test-keycloak

e2e: e2e-cluster e2e-images e2e-harness e2e-install e2e-suite

e2e-cluster:
	kind get clusters | grep -qx $(KIND_CLUSTER) || kind create cluster --name $(KIND_CLUSTER) --wait 2m

# The images the chart and the harness reference as local/<name>:ci.
e2e-images:
	docker build -t local/authz-agent:ci               -f build/authz-agent/Dockerfile .
	docker build -t local/authz-policy-admin:ci        -f build/authz-policy-admin/Dockerfile .
	docker build -t local/pip-stub:ci                  -f test/integration/pipstub/Dockerfile test/integration/pipstub
	docker build -t local/authz-runtime-suite:ci       -f test/integration/testify/Dockerfile .
	docker build -t local/authz-parity-suite:ci        -f test/parity/suite/Dockerfile test/parity/suite
	docker build -t local/authz-test-keycloak:ci       -f test/keycloak/Dockerfile .
	kind load docker-image --name $(KIND_CLUSTER) $(addprefix local/,$(addsuffix :ci,$(E2E_IMAGES)))

# Keycloak with the test realms built into its image, the two stubs, and the
# M2M client-credentials Secret the chart expects the platform to provision.
e2e-harness:
	kubectl --context kind-$(KIND_CLUSTER) create namespace $(E2E_NAMESPACE) --dry-run=client -o yaml | kubectl --context kind-$(KIND_CLUSTER) apply -f -
	$(E2E_KUBECTL) create secret generic authz-agent-client-credentials --from-file=username=$(E2E_AUTHN)/m2m-credentials/username --from-file=password=$(E2E_AUTHN)/m2m-credentials/password --from-literal=name=authz-agent --dry-run=client -o yaml | $(E2E_KUBECTL) apply -f -
	$(E2E_KUBECTL) apply -f test/k8s/keycloak.yaml -f test/k8s/pip-stub.yaml -f test/k8s/entitlements-mock.yaml
	$(E2E_KUBECTL) rollout status deploy/pip-stub --timeout=2m
	$(E2E_KUBECTL) rollout status deploy/entitlements-mock --timeout=2m
	$(E2E_KUBECTL) rollout status deploy/keycloak --timeout=10m

# The stub first: the agent reports Ready only once it has pulled its policies,
# so its --wait would run out with no policy source to pull from.
e2e-install:
	helm --kube-context kind-$(KIND_CLUSTER) upgrade --install authz-policy-admin helm-templates/authz-policy-admin -n $(E2E_NAMESPACE) -f test/k8s/policy-admin-values.yaml --wait --timeout 5m $(E2E_HELM_ARGS)
	helm --kube-context kind-$(KIND_CLUSTER) upgrade --install authz-agent helm-templates/authz-agent -n $(E2E_NAMESPACE) -f test/k8s/values.yaml --wait --timeout 5m $(E2E_HELM_ARGS)

# Streams the suite log; the final wait turns the Job outcome into the exit code.
# The Job manifest carries the chart's Service; sed swaps in E2E_BASE_URL.
e2e-suite:
	$(E2E_KUBECTL) delete job runtime-suite --ignore-not-found
	sed 's|value: http://authz-agent:8080$$|value: $(E2E_BASE_URL)|' \
	    test/k8s/runtime-suite-job.yaml | $(E2E_KUBECTL) apply -f test/k8s/runtime-suite-rbac.yaml -f -
	$(E2E_KUBECTL) wait --for=condition=Ready pod -l job-name=runtime-suite --timeout=3m
	$(E2E_KUBECTL) logs -f job/runtime-suite
	$(E2E_KUBECTL) wait --for=condition=Complete job/runtime-suite --timeout=1m

# `make e2e-images` rebuilds the local images under the same tags, and a
# running Pod keeps the old content: the kubelet never re-reads a tag it
# already has. Restart every Deployment that runs a local image and wait until
# it is Ready again, so the next `e2e-suite` tests the new build.
E2E_LOCAL_DEPLOYMENTS := authz-agent authz-policy-admin pip-stub entitlements-mock keycloak
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

parity: e2e-cluster e2e-images parity-harness parity-install parity-suite

# Keycloak with the test realms built into its image, the two stubs, and the
# M2M client-credentials Secret for the parity-m2m client of the cloud-common
# realm.
parity-harness:
	kubectl --context kind-$(KIND_CLUSTER) create namespace $(PARITY_NAMESPACE) --dry-run=client -o yaml | kubectl --context kind-$(KIND_CLUSTER) apply -f -
	$(PARITY_KUBECTL) create configmap pip-mock-config --from-file=test/integration/pipstub/config/requestargs.responses.yaml --dry-run=client -o yaml | $(PARITY_KUBECTL) apply -f -
	$(PARITY_KUBECTL) create secret generic authz-agent-client-credentials --from-literal=username=parity-m2m '--from-literal=password=ParityM2MSecret1!@#' --from-literal=name=authz-agent --dry-run=client -o yaml | $(PARITY_KUBECTL) apply -f -
	$(PARITY_KUBECTL) apply -f test/k8s/parity/keycloak.yaml -f test/k8s/parity/pip-mock.yaml -f test/k8s/parity/entitlements-mock.yaml
	$(PARITY_KUBECTL) rollout status deploy/pip-mock --timeout=2m
	$(PARITY_KUBECTL) rollout status deploy/entitlements-mock --timeout=2m
	$(PARITY_KUBECTL) rollout status deploy/idp --timeout=10m

# The stub first, as in e2e-install.
parity-install:
	helm --kube-context kind-$(KIND_CLUSTER) upgrade --install authz-policy-admin helm-templates/authz-policy-admin -n $(PARITY_NAMESPACE) -f test/k8s/parity/policy-admin-values.yaml --wait --timeout 5m $(E2E_HELM_ARGS)
	helm --kube-context kind-$(KIND_CLUSTER) upgrade --install authz-agent helm-templates/authz-agent -n $(PARITY_NAMESPACE) -f test/k8s/parity/values.yaml --wait --timeout 5m $(E2E_HELM_ARGS)

# Streams the suite log; the final wait turns the Job outcome into the exit code.
# As e2e-suite: sed swaps PARITY_AC_BASE_URL into the Job manifest.
parity-suite:
	$(PARITY_KUBECTL) delete job parity-suite --ignore-not-found
	sed 's|value: http://authz-agent:8080$$|value: $(PARITY_AC_BASE_URL)|' test/k8s/parity/parity-suite-job.yaml | $(PARITY_KUBECTL) apply -f -
	$(PARITY_KUBECTL) wait --for=condition=Ready pod -l job-name=parity-suite --timeout=3m
	$(PARITY_KUBECTL) logs -f job/parity-suite
	$(PARITY_KUBECTL) wait --for=condition=Complete job/parity-suite --timeout=1m

# The parity counterpart of e2e-restart, for the same reason.
PARITY_LOCAL_DEPLOYMENTS := authz-agent authz-policy-admin pip-mock entitlements-mock idp
parity-restart:
	$(PARITY_KUBECTL) rollout restart $(addprefix deploy/,$(PARITY_LOCAL_DEPLOYMENTS))
	for d in $(PARITY_LOCAL_DEPLOYMENTS); do $(PARITY_KUBECTL) rollout status deploy/$$d --timeout=3m || exit 1; done

parity-logs:
	mkdir -p $(E2E_ARTIFACTS)/parity
	kind export logs --name $(KIND_CLUSTER) $(E2E_ARTIFACTS)/parity/cluster
	$(PARITY_KUBECTL) get events --sort-by=.lastTimestamp > $(E2E_ARTIFACTS)/parity/events.txt
	-$(PARITY_KUBECTL) exec deploy/pip-mock -- wget -qO- http://authz-agent:8080/internal/v1/decision-logs > $(E2E_ARTIFACTS)/parity/decision-logs.jsonl

.PHONY: lint install-hooks e2e e2e-cluster e2e-images e2e-harness e2e-install e2e-suite e2e-restart e2e-logs e2e-down parity parity-harness parity-install parity-suite parity-restart parity-logs
