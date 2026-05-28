# APIM Rate Limit Compiler Test Harness

This test project verifies generated APIM policy fragments at several levels. Snapshot tests still provide the primary review surface for generated XML, but the harness adds structural checks, expression compilation, and a small executable model of the generated policy subset.

## Test Layers

The tests intentionally cover different failure modes:

- `CompilerSnapshotTests` keeps byte-for-byte fixture snapshots and deterministic output checks.
- `GeneratedPolicyContract` validates that generated XML stays inside the compiler-owned fragment subset.
- `PolicyExpressionExtractor` finds APIM policy expressions in generated XML attributes.
- `PolicyExpressionCompiler` compiles extracted `@(...)` and `@{...}` expressions with Roslyn using C# 7.3 syntax.
- `PolicyHarness` executes the supported generated XML subset against a fake APIM context.

Do not replace snapshots with harness tests. Snapshots are still useful because generated APIM fragments are reviewed deployment artifacts. The harness exists to catch semantic regressions that string assertions and snapshots can miss.

## Supported XML Subset

The local harness only models the XML emitted by this compiler:

- `fragment`
- `choose`
- `when`
- `otherwise`
- `set-variable`
- `rate-limit-by-key`

It does not model full APIM policy behavior. In particular, it does not simulate APIM rate-limit counters or gateway-side policy deployment validation. A recorded `AppliedRateLimit` means the generated policy reached a `rate-limit-by-key` statement and evaluated its `counter-key`.

## Expression Compilation

APIM expressions are embedded in XML attributes. The compiler extracts these attributes and wraps them into generated C# like this:

- `@(...)` becomes `return ...;`
- `@{...}` becomes a statement body and must return on every path

The generated code is compiled dynamically with Roslyn and references this test assembly. That is why some fake APIM helpers may look unused to normal static search.

Important dynamic dependencies:

- `FakeContext`, `FakeRequest`, and `FakeUrl` provide the `context` object shape used by generated expressions.
- `JwtFixture` creates deterministic unsigned bearer tokens for resolver behavior tests.

Do not delete these just because an IDE or text search does not find direct C# calls. The calls are inside generated expression text compiled at test runtime.

## Current Preamble Behavior

The generated preamble uses specialized JWT payload scanning for the claims it needs. It does not call `.AsJwt()` and does not use a general JSON parser.

The harness enforces this at two levels:

- `PolicyExpressionCompiler.ValidateStaticPolicySubset` rejects `.AsJwt()` and stale token-substring patterns.
- `PolicyHarness` behavior tests verify client ID and scope resolution, including claim order, whitespace around `:`, missing claims, and preserving existing public variables.

## Adding Tests

Prefer behavior-level harness tests when checking policy semantics:

- whether a request applies a rate limit
- which counter key is produced
- whether caller variables are resolved or preserved
- whether exclusions prevent rate limiting

Prefer contract tests for XML shape and required attributes. Use direct string assertions only for intentional generated text details that cannot be expressed structurally or behaviorally.

Run the suite with:

```bash
dotnet test
```

For analyzer checks:

```bash
dotnet build tests/ApimRateLimitCompiler.Tests/ApimRateLimitCompiler.Tests.csproj --no-restore -warnaserror /p:AnalysisMode=AllEnabledByDefault /p:EnforceCodeStyleInBuild=true
```
