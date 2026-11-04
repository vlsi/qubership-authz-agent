# lint: run all linters against the full tree (mirrors CI super-linter checks).
#
# Requires: golangci-lint, shellcheck, yamllint, npx (markdownlint-cli2),
#           python3, zizmor, helm, docker (for test-stand-files), hadolint,
#           kubeconform, trivy.  Install zizmor/yamllint: pip install yamllint zizmor
#           Install hadolint/kubeconform/trivy: mise install (versions in mise.toml)
lint: test-stand-files
	@echo "[lint] Go — root module"
	golangci-lint run ./...
	@echo "[lint] Go — test/parity/suite"
	cd test/parity/suite && golangci-lint run ./...
	@echo "[lint] Go — test/integration/testify"
	cd test/integration/testify && golangci-lint run --build-tags integration ./...
	@echo "[lint] Go — test/integration/pipstub"
	cd test/integration/pipstub && golangci-lint run ./...
	@echo "[lint] Go — test/integration/tenantmanager"
	cd test/integration/tenantmanager && golangci-lint run ./...
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
	@echo "[lint] Dockerfiles and rendered charts"
	bash test/scripts/lint-images-and-charts.sh
	@echo "[lint] GitHub Actions (zizmor)"
	$${ZIZMOR_BIN:-$${HOME}/.local/bin/zizmor} --config .github/linters/zizmor.yaml \
	    .github/workflows/*.yaml .github/workflows/*.yml
	@echo "[lint] All checks passed."

# install-hooks: point git at the bundled hooks directory.
install-hooks:
	git config core.hooksPath .githooks
	@echo "[install-hooks] pre-commit hook active (core.hooksPath=.githooks)"

# test-jayway: compare internal/jsonpath with Jayway JsonPath on the JVM.
# Needs java 17 or later and mvn; Maven resolves the Jayway jars from
# testdata/jayway/pom.xml. Set JSONPATH_COMPARISON_DIR to a checkout of
# github.com/cburgmer/json-path-comparison to run its queries too, and
# JAYWAY_SUITE_CALLS to the directory jayway-suite-calls wrote to run the
# paths and documents of Jayway's own tests.
JAYWAY_DIR := internal/jsonpath/testdata/jayway
test-jayway:
	mvn -q -B -f $(JAYWAY_DIR)/pom.xml dependency:build-classpath -Dmdep.outputFile=$(CURDIR)/$(JAYWAY_DIR)/target/classpath.txt
	test -s $(JAYWAY_DIR)/target/classpath.txt
	JAYWAY_CLASSPATH="$$(cat $(JAYWAY_DIR)/target/classpath.txt)" go test -count=1 -tags jayway -run Jayway ./internal/jsonpath/

# jayway-suite-calls: run the tests of Jayway JsonPath with the agent in
# testdata/jayway/recorder, which writes the path and the document of every
# read they make into JAYWAY_SUITE_CALLS, replacing the calls-*.jsonl files a
# previous run left there. Set JAYWAY_SRC_DIR to a checkout of
# github.com/json-path/JsonPath at tag json-path-2.9.0. Its Gradle 7.4.2 runs
# on java 17, not on 21. A failing Jayway test does not fail the target.
jayway-suite-calls:
	test -n "$(JAYWAY_SRC_DIR)" -a -n "$(JAYWAY_SUITE_CALLS)"
	mvn -q -B -f $(JAYWAY_DIR)/recorder/pom.xml package
	rm -f "$(JAYWAY_SUITE_CALLS)"/calls-*.jsonl
	cd "$(JAYWAY_SRC_DIR)" && ./gradlew --quiet --no-daemon \
	    --init-script $(CURDIR)/$(JAYWAY_DIR)/recorder/record.gradle \
	    -PrecorderJar=$(CURDIR)/$(JAYWAY_DIR)/recorder/target/recorder.jar \
	    -PrecorderOut="$(abspath $(JAYWAY_SUITE_CALLS))" \
	    :json-path:test :json-path-assert:test

# ── kind end-to-end ──────────────────────────────────────────────────────────
# Install the chart on a kind cluster and run the runtime suite against it.
# `make e2e` runs every step; CI calls the same targets one by one. See
# test/k8s/README.md.
KIND_CLUSTER ?= authz-e2e
E2E_NAMESPACE ?= authz-e2e
E2E_ARTIFACTS ?= test/artifacts/kind
E2E_KUBECTL := kubectl --context kind-$(KIND_CLUSTER) -n $(E2E_NAMESPACE)
E2E_HELM := helm --kube-context kind-$(KIND_CLUSTER) -n $(E2E_NAMESPACE)
# Extra arguments for the installs of the agent and authz-policy-admin charts,
# for example E2E_HELM_ARGS='--set IMAGE_PULL_POLICY=Never'. The test stand
# reads TAG and IMAGE_PULL_POLICY too, for images of its own, so it takes
# TEST_STAND_HELM_ARGS instead.
E2E_HELM_ARGS ?=
TEST_STAND_HELM_ARGS ?=
# How long `helm test` waits for each suite Job. A suite that runs longer
# raises this together with suite.activeDeadlineSeconds in its values.
E2E_SUITE_TIMEOUT ?= 15m
PARITY_SUITE_TIMEOUT ?= 15m
# How long a suite container may take to start before the suite target gives up.
SUITE_START_SECONDS ?= 180
# Where the suites send their requests: the chart's Service, which fronts the
# agent Pod.
E2E_BASE_URL ?= http://authz-agent:8080
PARITY_AC_BASE_URL ?= http://authz-agent:8080
E2E_IMAGES := authz-agent authz-policy-admin pip-stub tenant-manager \
              authz-runtime-suite authz-parity-suite
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
	docker build -t local/tenant-manager:ci            -f test/integration/tenantmanager/Dockerfile test/integration/tenantmanager
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

# Installs or upgrades the test-stand release with the helm arguments $(4).
# A dev-mode Keycloak mints new realm keys every time its container starts, and
# an agent that is already running keeps the JWKS it fetched at start, so the
# suite fails at setup.wait_for_agent. After the upgrade, an installed agent
# with a container older than the newest container of the Keycloak Deployment
# $(3) is restarted. The check reads the cluster rather than what this upgrade
# changed, so a retry after a failed upgrade that replaced Keycloak still
# restarts the agent. RFC 3339 timestamps in UTC sort as text.
# $(1) is kubectl, $(2) is helm.
define upgrade-test-stand
$(2) upgrade authz-test-stand $(TEST_STAND_CHART) $(4) --wait --timeout 10m
	started='{range .items[*]}{range .status.containerStatuses[*]}{.state.running.startedAt}{"\n"}{end}{end}'; \
	idp=$$($(1) get pods -l app=$(3) -o jsonpath="$$started" | sed '/^$$/d' | sort | tail -n 1); \
	agent=$$($(1) get pods -l name=authz-agent -o jsonpath="$$started" | sed '/^$$/d' | sort | head -n 1); \
	if [ -n "$$idp" ] && [ -n "$$agent" ] && [ "$$agent" != "$$idp" ] && \
	   [ "$$(printf '%s\n%s\n' "$$agent" "$$idp" | sort | head -n 1)" = "$$agent" ]; then \
		echo "authz-agent started at $$agent, before Keycloak got new realm keys at $$idp; restarting authz-agent."; \
		$(1) rollout restart deploy/authz-agent && $(1) rollout status deploy/authz-agent --timeout=3m; \
	fi
endef

# Non-empty when the variable $(1) was given on the command line or in the
# environment rather than taken from its default in this file.
given = $(filter command line environment override,$(origin $(1)))

# The test stand of test/k8s/test-stand-values.yaml: Keycloak with the realms
# of test/k8s/authn/, the two stubs, the tenant-manager emulator, the M2M
# client-credentials Secret the chart expects the platform to provision, and
# the runtime suite Job, which e2e-suite runs.
e2e-harness: test-stand-files
	$(call upgrade-test-stand,$(E2E_KUBECTL),$(E2E_HELM),keycloak,--install --create-namespace -f test/k8s/test-stand-values.yaml --set suite.env.BASE_URL=$(E2E_BASE_URL) $(TEST_STAND_HELM_ARGS))

# The stub first: the agent reports Ready only once it has pulled its policies,
# so its --wait would run out with no policy source to pull from. Each chart
# takes its dev resource profile, since values.yaml carries no sizing.
e2e-install:
	$(E2E_HELM) upgrade --install authz-policy-admin helm-templates/authz-policy-admin -f helm-templates/authz-policy-admin/resource-profiles/dev.yaml -f test/k8s/policy-admin-values.yaml --wait --timeout 5m $(E2E_HELM_ARGS)
	$(E2E_HELM) upgrade --install authz-agent helm-templates/authz-agent -f helm-templates/authz-agent/resource-profiles/dev.yaml -f test/k8s/values.yaml --wait --timeout 5m $(E2E_HELM_ARGS)

# `helm test` runs the suite Job of the test stand and exits with its outcome.
# Without --logs it prints no log, and --logs reads Pods only, so the target
# streams the Job's log itself.
# `kubectl logs` fails until the Job has a Pod whose container has started, so
# the loop polls until SUITE_START_SECONDS have passed since helm test began;
# --pod-running-timeout keeps one attempt from waiting the default 20 s for a
# Pod. A container that has not started by then, for example on
# ErrImageNeverPull or a Pod the Job cannot create, will not: the target prints
# the Pods and stops helm test rather than wait out its timeout. The loop also
# ends when helm test exits on its own, for example when the release is missing.
# Once the log ends, a Job that failed stops helm test too: Helm 4.0 to 4.1.0
# wait out --timeout on a failed Job, so the target reads the Job's status for
# up to a minute rather than rely on helm to notice.
# $(1) is kubectl, $(2) is helm, $(3) is the Job name, $(4) is how long helm
# waits for the Job, no shorter than its suite.activeDeadlineSeconds.
define run-suite
$(1) delete job $(3) --ignore-not-found --wait
$(2) test authz-test-stand --timeout $(4) & helm_pid=$$!; \
	deadline=$$(( $$(date +%s) + $(SUITE_START_SECONDS) )); started=; \
	while kill -0 $$helm_pid 2>/dev/null; do \
		if $(1) logs job/$(3) --pod-running-timeout=2s >/dev/null 2>&1; then started=1; break; fi; \
		if [ "$$(date +%s)" -ge "$$deadline" ]; then \
			echo "The $(3) container did not start within $(SUITE_START_SECONDS) seconds:"; \
			$(1) get pods -l job-name=$(3) -o wide; \
			kill $$helm_pid; wait $$helm_pid; exit 1; \
		fi; \
		sleep 2; \
	done; \
	if [ -n "$$started" ]; then $(1) logs -f job/$(3); else $(1) logs job/$(3) 2>/dev/null || true; fi; \
	deadline=$$(( $$(date +%s) + 60 )); \
	while kill -0 $$helm_pid 2>/dev/null && [ "$$(date +%s)" -lt "$$deadline" ]; do \
		if [ "$$($(1) get job/$(3) -o jsonpath='{.status.failed}' 2>/dev/null)" -gt 0 ] 2>/dev/null; then \
			echo "The $(3) Job failed; stopping helm test."; \
			kill $$helm_pid; wait $$helm_pid; exit 1; \
		fi; \
		sleep 2; \
	done; \
	wait $$helm_pid
endef

# The suite Job reads E2E_BASE_URL from the release values. Given explicitly,
# it is written there before the run; otherwise the run keeps the URL the
# release has.
e2e-suite: $(if $(call given,E2E_BASE_URL),test-stand-files)
ifneq ($(call given,E2E_BASE_URL),)
	$(call upgrade-test-stand,$(E2E_KUBECTL),$(E2E_HELM),keycloak,--reuse-values --set suite.env.BASE_URL=$(E2E_BASE_URL))
endif
	$(call run-suite,$(E2E_KUBECTL),$(E2E_HELM),runtime-suite,$(E2E_SUITE_TIMEOUT))

# `make e2e-images` rebuilds the local images under the same tags, and a
# running Pod keeps the old content: the kubelet never re-reads a tag it
# already has. Restart every Deployment that runs a local image and wait until
# it is Ready again, so the next `e2e-suite` tests the new build. Keycloak runs
# the public image; `make e2e-harness` restarts it when a realm file changes,
# and the agent with it.
E2E_LOCAL_DEPLOYMENTS := authz-agent authz-policy-admin pip-stub entitlements-mock tenant-manager
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
# test/parity/suite/testdata/realm/, pip-mock,
# entitlements-mock, the M2M client-credentials Secret for the parity-m2m
# client of the cloud-common realm, and the parity suite Job, which
# parity-suite runs.
parity-harness: test-stand-files
	$(call upgrade-test-stand,$(PARITY_KUBECTL),$(PARITY_HELM),idp,--install --create-namespace -f test/k8s/parity/test-stand-values.yaml --set suite.env.PARITY_AC_BASE_URL=$(PARITY_AC_BASE_URL) $(TEST_STAND_HELM_ARGS))

# The stub first, as in e2e-install.
parity-install:
	$(PARITY_HELM) upgrade --install authz-policy-admin helm-templates/authz-policy-admin -f helm-templates/authz-policy-admin/resource-profiles/dev.yaml -f test/k8s/parity/policy-admin-values.yaml --wait --timeout 5m $(E2E_HELM_ARGS)
	$(PARITY_HELM) upgrade --install authz-agent helm-templates/authz-agent -f helm-templates/authz-agent/resource-profiles/dev.yaml -f test/k8s/parity/values.yaml --wait --timeout 5m $(E2E_HELM_ARGS)

# As e2e-suite, for PARITY_AC_BASE_URL.
parity-suite: $(if $(call given,PARITY_AC_BASE_URL),test-stand-files)
ifneq ($(call given,PARITY_AC_BASE_URL),)
	$(call upgrade-test-stand,$(PARITY_KUBECTL),$(PARITY_HELM),idp,--reuse-values --set suite.env.PARITY_AC_BASE_URL=$(PARITY_AC_BASE_URL))
endif
	$(call run-suite,$(PARITY_KUBECTL),$(PARITY_HELM),parity-suite,$(PARITY_SUITE_TIMEOUT))

# The parity counterpart of e2e-restart, for the same reason.
PARITY_LOCAL_DEPLOYMENTS := authz-agent authz-policy-admin pip-mock entitlements-mock
parity-restart:
	$(PARITY_KUBECTL) rollout restart $(addprefix deploy/,$(PARITY_LOCAL_DEPLOYMENTS))
	for d in $(PARITY_LOCAL_DEPLOYMENTS); do $(PARITY_KUBECTL) rollout status deploy/$$d --timeout=3m || exit 1; done

parity-logs:
	mkdir -p $(E2E_ARTIFACTS)/parity
	kind export logs --name $(KIND_CLUSTER) $(E2E_ARTIFACTS)/parity/cluster
	$(PARITY_KUBECTL) get events --sort-by=.lastTimestamp > $(E2E_ARTIFACTS)/parity/events.txt
	-$(PARITY_KUBECTL) exec deploy/pip-mock -- wget -qO- http://authz-agent:8080/internal/v1/decision-logs > $(E2E_ARTIFACTS)/parity/decision-logs.jsonl

.PHONY: lint install-hooks test-jayway jayway-suite-calls e2e e2e-cluster e2e-images test-stand-files e2e-harness e2e-install e2e-suite e2e-restart e2e-logs e2e-down parity parity-harness parity-install parity-suite parity-restart parity-logs
