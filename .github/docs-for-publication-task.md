# Notes for the publication task

This file lists the GitHub API operations that must be performed after the internal
review, when the repository is made public.  They are GitHub settings
and cannot be applied as files in the working tree.

## Repository settings

### Topics

Set these topics on the repository:

```text
core  authz  go  qubership-core
```

Do **not** use `cloud-core` — that tag marks the companion-agent tier
(`qubership-core-*` services that ship beside a product consumer).
`qubership-authz-agent` is a standalone product at the same tier as
`qubership-maas` and `qubership-core-dbaas-agent`.

### Forking

Enable forking for the repository (disabled by default for org repos).

### Central topic registry

Register the repository in `Netcracker/.github/config/topics.json` under the
`core` and `authz` topics.  This file is maintained by a separate team; open a
PR there after publication.  It is parked here rather than blocked on it.

## Secrets and variables

The workflows in `.github/workflows/` expect the following to be configured on
the repository.

### Variables (`vars.*`)

| Variable | Used by | Purpose |
| --- | --- | --- |
| `SONAR_PROJECT_KEY` | `go-build.yaml` | SonarQube project key for code-quality scans |
| `SONAR_ORGANIZATION` | `go-build.yaml` | SonarQube organisation (set at org level) |
| `SONAR_HOST_URL` | `go-build.yaml` | SonarQube server URL (set at org level) |

### Secrets (`secrets.*`)

| Secret | Used by | Purpose |
| --- | --- | --- |
| `SONAR_TOKEN` | `go-build.yaml` | Token to authenticate to SonarQube |
| `CLA_ACCESS_TOKEN` | `cla.yaml` | Personal access token for the CLA assistant to write to `cla-storage` |
| `GITHUB_TOKEN` | `go-build.yaml` and all release workflows | Automatically provided by GitHub Actions; no manual setup needed |

`SONAR_ORGANIZATION`, `SONAR_HOST_URL`, and `SONAR_TOKEN` are typically configured at the
organisation level and shared with the repository. Verify that this repository can read them
before the first CI run. Without `SONAR_PROJECT_KEY`, `go-build.yaml` skips the
Sonar analysis.

## Branch protection

Apply the organisation's standard branch-protection rule to `main`:

- Require PR reviews (at least 1 approver from CODEOWNERS)
- Require status checks to pass (`CI gate` from `integration-tests.yaml`, `Build gate` from `go-build.yaml`,
  `Lint gate` from `super-linter.yaml`)
- Require branches to be up to date before merging

The organisation's `Netcracker/.github/config/Protect-main-branch.json` contains
the canonical rule configuration.

## Container registry

Images are pushed to `ghcr.io/netcracker/` on release, and dev images on every push to `main` or
`lts/**` and every pull request from a branch of this repository (`go-build.yaml`). Both workflows use
`GITHUB_TOKEN` (automatic) for authentication to the GitHub Container Registry.
No additional secrets are needed.
