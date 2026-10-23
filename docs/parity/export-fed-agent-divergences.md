# Divergences of the export-fed agent from legacy access-control

## Status

Proposed. The suite applies the decisions below (`acceptedExportDivergences` in
[`test/parity/suite/accepted_divergences.go`](../../test/parity/suite/accepted_divergences.go)); the repository
maintainers confirm or reject them.

## Context

The agent can pull its configuration from a legacy access-control installation: it fetches the v3 configuration
export (`/access/v3/config/policySets`, `/access/v3/config/pips`) and converts it in `internal/acconfig`. The
export-fed parity profile (`TestExportFedAgent`, `make parity-export`) feeds the agent the exports that the executable
specification predicts for every recorded parity case, and compares the agent's decisions with the legacy goldens.
Each golden of the bundle carries the class of the difference the specification predicts:

| Class | What differs | Legacy reads it |
| --- | --- | --- |
| `set-type` | The decision rests on a regular policy set (type `DEFAULT`), which the conversion skips | Yes: without its regular sets, the legacy decision differs from the golden |
| `tenant` | The conversion merges the policies and PIPs of every tenant in the export | No: legacy keeps the tenants apart, and its export carries every tenant |
| `conversion` | The conversion of the tenant's own simplified sets loses what legacy reads: the condition and the predicates of a policy of every operation or resource type, the component | Yes |
| `pip-kind` | A policy reads a PIP the conversion drops: `MAPPING`, `FILTERED`, `PERMISSION_SCOPE`, `GENERAL` with a `beanName` or without a `pipType` | Yes |
| `pull-failure` | The agent cannot convert the export at all and keeps the documents of its last good pull, or, for a PIP name shorter than `subject.`, its normalization panics and the agent stops | Not applicable |

## Decision

The `set-type` class is accepted. The agent evaluates the simplified model only: `internal/acconfig` skips every
policy set whose type is not `SIMPLIFIED`, and the agent has no evaluator for regular policy sets. A legacy
installation whose decisions rest on regular sets cannot be served by the agent; the export-fed profile reports such a
golden as an accepted divergence when the agent answers as the bundle predicts.

The `undeclared-pip` class of part A is accepted too, wrong allows included. A rule of a simplified policy reads
`subject.<attribute>`, the attribute is neither one the agent resolves on its own (`id`, `name`, `type`, `roles`,
`scopes`, `entitledResources`) nor the first segment of the name of a PIP in the export, and the PAP keeps the rule
anyway. Legacy fails the whole rule on such an attribute and denies. The agent takes the attribute as missing, which
makes only the comparison that reads it unknown, and evaluates the rest of the condition, so
`subject.x == 'v' OR resource.a == 'y'` allows a request with `resource.a` equal to `y`. The agent's answer is the
intended one: the order of the operands of `OR` decides nothing, and a missing attribute does not end the evaluation
of the condition.

The other classes are not accepted; they are defects of the conversion:

- `tenant` produces wrong allows: a simplified policy of one tenant allows a request in another. In part A a
  decision also gets this class when its request names a tenant and an element of the export belongs to another one,
  as with the export's tenant spelled in another case or with a space: the agent does not read the tenant of the
  request.
- `pull-failure` contradicts the converter's own rule that one bad element must not cost the agent every other
  policy: one value of an unexpected JSON type, or one condition the agent's parser refuses, fails the whole pull.
- `conversion` drops data the legacy decision reads, and produces wrong allows: a policy of every operation with a
  condition becomes an unconditional grant of its roles. `pip-kind` drops PIPs the legacy decision reads.

## Consequences

- A golden of class `set-type` passes only when the agent's answer equals the answer the bundle predicts for it, so a
  change of the agent's behavior on regular sets still fails the profile.
- An answer that allows what the golden denies is accepted only for a class whose decision says so, which is
  `undeclared-pip` alone: the profile compares the agent's grants with the golden's before it looks up the
  class. Of the 2904 `set-type` goldens of the first bundle,
  2580 are wrong denies, 268 differ in the status of the response only, and 56 are filter texts whose difference has
  no direction the profile can tell; none is a wrong allow. Legacy combines its top-level policy sets so that any
  permit wins, so a regular set the agent skips can only take an allow away. A legacy installation that fails a whole
  decision on a regular set (a PIP of that set answers with an error) is the exception to watch for when the bundle
  grows.
- When the agent gains an evaluator for regular policy sets, this entry is removed, and the profile then compares
  those goldens with legacy directly.
- Part A of the profile (`TestExportFedLegacyAgent`, `make parity-export-legacy`) mounts the exports legacy
  access-control recorded, and has no prediction of the agent's answer. There a golden whose point holds a regular
  policy set (class `set-type`) passes when the agent allows nothing the golden denies. Its other classes are
  `pull-failure`, the remaining export features (`status`, `rule-effect`, `customization`, `tenant`, `pip-kind`,
  `undeclared-pip`), and `agent` for a difference at a point with none of them, which is a defect of the agent's
  evaluation rather than of the conversion. A difference of class `undeclared-pip` is accepted whatever the agent
  answers. The class belongs to the point, not to the rule: a decision gets it when any rule of the point's export
  reads an undeclared attribute and no feature earlier in the order of `exportFeatures` applies, so a wrong allow
  that another rule of the same export causes is accepted as well.
