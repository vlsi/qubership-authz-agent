# Evaluate jsonPath with our own Go package instead of a third-party library

## Status

Proposed

<!-- markdownlint-disable-next-line MD001 -->
#### Date

#### Owner

vlsi

#### Participants and approvers

The Netcracker/qubership-authz-agent maintainers. Assumption: the approvers' GitHub accounts are added when this record
is reviewed.

#### Related ADRs

- [authz-agent-ADR-0080: Replace Envoy, the Lua filters, and the OPA container with one Go service that embeds OPA](20260907-authz-agent-adr-0080-single-go-service-with-embedded-opa.md):
  the agent is one Go process. A jsonPath evaluator has to run inside it, in Go.

## Context

Policies written for legacy access-control use jsonPath in three places:

- the `jsonPath` of a GENERAL PIP declaration, which selects a value from the PIP response;
- the `claim` of a TOKEN PIP declaration, which selects a value from the token, as in `$.realm_access.roles`;
- a resource attribute in a condition or a target, such as `resource.items[?(@.role == 'owner')].userId[*]`.

Legacy access-control does not evaluate these paths itself. It drops the `resource.` prefix and passes the rest to
Jayway JsonPath 2.9.0 or 2.10.0 in its default configuration (the json-smart provider, no options). Around the library
it adds its own rules: a path that Jayway does not find makes the attribute absent, and a list becomes a set. The agent
has to answer as legacy does, so the reference is Jayway together with these rules, not a jsonPath standard.

The first release supports the subset of jsonPath that the parity goldens record (PR #42): `.key`, `['key']`, `..key`,
`[n]`, `[n,m]`, `[a:b]`, `[*]`, the filter `[?(...)]` with `==`, `!=`, `<`, `<=`, `>`, `>=`, `in`, `nin`, `subsetof`,
`anyof`, `noneof`, `size`, `empty`, `=~`, `&&`, `||`, and the trailing functions `.length()`, `.min()`, `.max()`,
`.avg()`, `.sum()`, `.first()`, `.last()`, `.keys()`. A path outside the subset is reported as unsupported. Full Jayway
compatibility is the goal of a later step, one path form at a time.

The parity goldens show behavior that belongs to Jayway or to the legacy rules around it, and that RFC 9535 and most
libraries do not share:

- A filter compares a number with a quoted literal by value (`'5.0' == 5` holds), compares numbers as `BigDecimal`,
  and selects an element without the key for `!=` and `nin`.
- A filter applied to a single object tests the object itself.
- `[*]` applied to an object returns the member values.
- The answer distinguishes a missing key, a key under `null` or `{}`, and an index past the end of a list, because
  legacy reaches each of them through a different Jayway exception.

Real project configurations also use forms that several libraries do not parse: `$.[*].id`, a claim with a hyphen that
Jayway reads as `$.user-id`, an index written after a dot (`$.roles.1`), `null` as a filter literal
(`@.groups == null`), and a regular expression with a flag (`@.name =~ /admin.*/i`).

We compared seven Go libraries with Jayway 2.9.0 on the same inputs: `github.com/ohler55/ojg/jp`,
`github.com/theory/jsonpath`, `github.com/AsaiYusuke/jsonpath/v2`, `github.com/spyzhov/ajson`,
`github.com/bhmj/jsonslice`, `github.com/PaesslerAG/jsonpath`, and `github.com/oliveagle/jsonpath`. The inputs were the
258 queries of [json-path-comparison](https://github.com/cburgmer/json-path-comparison) and 88 cases of legacy behavior
from the agent's tests. `k8s.io/client-go/util/jsonpath` and `github.com/vmware-labs/yaml-jsonpath` were left out: the
first implements the kubectl dialect and brings in all of client-go, the second works on YAML nodes.

| Library | Answers equal to Jayway, of 258 | Legacy cases passed, of 88 |
| --- | --- | --- |
| `theory/jsonpath` (RFC 9535) | 168 | 41 |
| `ohler55/ojg/jp` | 164 | 47 |
| `AsaiYusuke/jsonpath/v2` | 162 | 31 |
| `bhmj/jsonslice` | 151 | 46 |
| `spyzhov/ajson` | 150 | 41 |
| `PaesslerAG/jsonpath` | 150 | 18 |
| `oliveagle/jsonpath` | 77 | 17 |

None of the libraries claims Jayway compatibility. None parses `nin`, `subsetof`, `anyof`, `noneof`, or `size` in a
filter. None accepts `.min()`, `.sum()`, or `.keys()` at the end of a path. Only `bhmj/jsonslice` returns a value for
`.length()`, and for a string it counts bytes.

## Decision

We will evaluate jsonPath with our own Go package in the agent, `internal/jsonpath`, and take no third-party jsonPath
library as a runtime dependency.

- The package parses the path and evaluates it over the agent's value model, which keeps every number as its exact
  decimal text and keeps the order of object members.
- The package answers as Jayway does, over a document whose numbers are exact, wherever the answer is Jayway's own. It
  departs from Jayway where the legacy service reads Jayway's answer in its own way, and where Jayway 2.9.0 has a bug:
  there the package gives the answer Jayway means to give, and the agent deliberately differs from legacy. The Neutral
  consequences list the first, the Negative ones the second.
- The release supports the subset listed in the Context, plus the forms of real configurations: `$.[*]` and any other
  bracket step after a dot, a key with a hyphen, an index written after a dot, and `null` as a filter literal. A path
  outside the subset fails to compile with an unsupported-path error, so the policy that holds it is refused before
  it runs. So does a regular expression Go cannot match the way `java.util.regex` does. A path Jayway refuses to
  compile, such as `[:]`, an index or a slice bound beyond the `int` range, or a digit outside the Basic Multilingual
  Plane in an index or a filter number, compiles and selects nothing: the legacy service catches Jayway's exception
  and reads the attribute as absent, and so does the specification.
- Each further Jayway form is added as its own change, with cases that run against Jayway.
- A differential test runs the package and Jayway JsonPath 2.9.0 on the JVM over the same inputs: the package's own
  cases, the queries of json-path-comparison, and the paths and documents that Jayway's own tests read, recorded by a
  Java agent while those tests run. Jackson reads each document for Jayway with every number that has a
  fraction or an exponent as a `BigDecimal`: a golden for a number beyond the `double` range shows that legacy hands
  Jayway exact numbers, and a document json-smart reads makes Jayway throw there instead. The test runs in CI as its own
  job and locally as `make test-jayway`, and is not part of the default `go test ./...`. Each answer that differs from
  Jayway's is listed in the test with what Jayway does, and the test fails on a difference that is not listed.

### Justification

The behavior that has to match sits in the core of a jsonPath library: the syntax of the filter and the way the filter
compares values. Neither can be changed from outside the libraries we compared. The filter operators of
`ohler55/ojg/jp` are unexported package variables. `theory/jsonpath` registers only function extensions in RFC 9535
syntax, and an infix operator such as `nin` is not one of them. A wrapper around a library would need its own path
tokenizer for the forms the library rejects, a step-by-step walk to tell a missing key from a key under `null` and from
an index past the end, its own trailing functions, and its own filter language. What remains for the library is `.key`,
`[n]`, `[*]`, and `..key`, which are the simplest part of the evaluator.

The best library, `ohler55/ojg/jp`, fails 41 of the 88 legacy cases. Nineteen of them are trailing functions and twenty
are in the filter: the operators it does not parse, the comparison of a number with a string, the flag `/i`, and a
filter applied to a single object. The package written for the first release passes all 88.

Alternatives considered:

- **Use `github.com/ohler55/ojg/jp` and wrap it.** It is the most active candidate, it has no dependencies, and it
  exposes the parsed path. Rejected for the reasons above: the wrapper would contain the whole filter language, and the
  library would still reject a key with a hyphen and `/i`.
- **Use `github.com/theory/jsonpath`.** It implements RFC 9535 strictly. Rejected: legacy follows Jayway, and the two
  dialects differ in the filter syntax and in what a filter over an object selects.
- **Fork a library and change its filter.** Rejected: the fork would carry the same amount of our code, inside a
  structure designed for a different dialect, and every upstream release would need a merge.
- **Call Jayway itself, in a JVM next to the agent.** Rejected: the agent is one Go process (ADR-0080), it has to run
  without Kubernetes, and a decision has a budget of 5 ms, which a call to another process per jsonPath would consume.

## Consequences

Positive:

- The agent answers the legacy cases exactly, including numbers outside the `float64` range and the distinction between
  a missing key, a `null` parent, and an index past the end.
- The agent has no jsonPath dependency to upgrade, audit, or patch.
- The differential test makes compatibility measurable: each new form is accepted when its answers match Jayway's.

Negative:

- We maintain a parser and an evaluator, about 1200 lines of Go plus tests, and we own their bugs.
- Regular expressions run on Go's RE2 engine, not on `java.util.regex`. The package rewrites a pattern into Go's syntax
  with the same matches: ASCII `\d`, `\w`, and `\s`, a `.` that stops at every line terminator, and a flag `i` that
  folds ASCII letters only. A pattern it cannot rewrite, such as one with lookaround, a backreference, `\b`, or `\p`,
  is reported as unsupported, not evaluated differently.
- The differential test needs a JVM, Maven to resolve the Jayway jars, a checkout of json-path-comparison, and a
  checkout of Jayway JsonPath at the tested tag, whose Gradle build runs on Java 17. The queries are under GPL-3.0, so
  CI checks them out from their own repository at a pinned commit, and they are not copied into this repository. CI
  records the calls of Jayway's tests in the same job, so the repository holds no copy of them either.
- The package does not repeat these bugs of Jayway 2.9.0, so the agent differs from legacy there. The differential test
  lists each case and fails once Jayway agrees with the package.

  | Input | Jayway 2.9.0 | The package |
  | --- | --- | --- |
  | `.max()` of numbers that are all zero or negative, `.min()` of an infinity | `4.9E-324` and `1.7976931348623157E308`: `max()` starts at `Double.MIN_VALUE`, `min()` at `Double.MAX_VALUE` ([json-path/JsonPath#942](https://github.com/json-path/JsonPath/issues/942)) | the largest or smallest number |
  | a slice `[a:b]` with a negative bound | a negative `a` wraps around the list, `[-4:1]` over five elements selects four of them and the first; a negative `b` is not counted from the end ([json-path/JsonPath#1076](https://github.com/json-path/JsonPath/issues/1076), [json-path/JsonPath#1081](https://github.com/json-path/JsonPath/pull/1081)) | a negative bound counts from the end, and a bound beyond the list stops at its edge |
  | `.last()` of a one-element list | an exception | the element |
  | `.first()` of an empty list after `[*]` over an object, `.last()` of an empty list after `[*]` | an exception, where `.first()` of an empty list element is dropped | the value is dropped |
  | `empty` over an object | `ClassCastException` | true where the object has no member |
  | `=~` over a missing member, `null`, or an object | matches it as empty text | no match |
  | a string in a document list under `subsetof`, `anyof`, `noneof`, or `=~` | a string that compiles as a path or parses as JSON becomes a path or JSON node, any other loses one pair of quotes and is unescaped; an object in the list throws | the string as it is; an object equals nothing and matches nothing |
  | a nested filter `[?(@.t[?(...)])]` | true where `t` is any list or object, as it tests only that the path exists | true where the inner filter selects an element of the list `t`, or holds for the object `t` |
  | an item of an `in`, `nin`, `subsetof`, `anyof`, or `noneof` list | unescaped twice, stripped of one pair of double quotes, and read as a path or JSON where it compiles or parses as one | unescaped once, as the literal of `==` is |

Neutral:

- The package departs from Jayway where the legacy service reads Jayway's answer in its own way. The differential test
  reads an exception as a path that selects nothing and lists the other difference.

  | Input | Jayway 2.9.0 | The package |
  | --- | --- | --- |
  | a path Jayway throws on while it reads it, such as a filter over a number, `.min()` over a list with no number, or a `null` document | an exception | nothing, as legacy ends the rule there as it does for a path Jayway does not find; goldens record it for `.first()` of an object and `.min()` over strings |
  | `.keys()` of an object | the set of keys | the text of the set, `[a, b]`, which a golden records |

- Where no golden records an answer, the package answers as Jayway does. That covers, among others, `.length()` of a
  string (`null`), `\d`, `\w`, `\s`, and the flag `i` over characters outside ASCII, `.` against `\r`, `in` with a
  number (compared by value), `<` between booleans (false), a filter or `[*]` after a step that selects several
  objects, `.keys()` of a scalar (`null`), and a function after a step that selects several values (computed for each
  value).
- `.sum()` and `.avg()` add from first to last, as Jayway does, so `[0.1, 0.2, 0.3]` sums to `0.6000000000000001`.
