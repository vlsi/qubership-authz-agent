# Agent instructions

Create an issue with a type (`gh issue create --type Bug|Feature|Task`), not a `bug` or `enhancement` label.

The Rego in `policies/` interprets simplified policies at run time and is maintenance-only until a translator from policies to Rego replaces it. Do not review it or report defects in it, and change it only to keep the existing tests passing.

Tests: Go `testing` from the standard library, with `testing/synctest` for code that waits on goroutines or timers. testify is used only in `test/integration` and `test/parity`; new tests elsewhere do not use it.
