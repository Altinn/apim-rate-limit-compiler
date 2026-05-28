# APIM Rate Limit Compiler

Deterministic .NET 10 CLI for compiling rate-limit JSON into Azure API Management policy fragment XML.

The compiler is intended for CI pipelines that keep rate-limit configuration as reviewed JSON and publish generated APIM `policyFragments` as build artifacts or deployment inputs.

## Projects

- `src/ApimRateLimitCompiler.Core`: JSON model, validation, diagnostics, hashing, and XML generation.
- `src/ApimRateLimitCompiler.Cli`: AOT-friendly command-line entrypoint.
- `tests/ApimRateLimitCompiler.Tests`: snapshot-focused tests for valid XML and invalid diagnostics.

## Requirements

- .NET SDK 10.0.100 or newer feature band.
- The repo includes `global.json` with `rollForward` set to `latestFeature`.

## Usage

Compile a rate-limit file to an APIM fragment:

```bash
dotnet run --project src/ApimRateLimitCompiler.Cli -- \
  rate-limit \
  --input rate-limits/dialogporten.json \
  --output generated/rate-limit-dialogporten.fragment.xml
```

The published native binary uses the same command shape:

```bash
apim-rate-limit-compiler rate-limit \
  --input rate-limits/dialogporten.json \
  --output generated/rate-limit-dialogporten.fragment.xml
```

Options:

- `--input <file>`: required JSON input.
- `--output <file>`: write generated fragment XML.
- `--stdout`: write generated fragment XML to stdout.
- `--write-hash <file>`: write SHA-256 hash of the generated XML.
- `--fail-on-warning`: return exit code `1` when validation warnings are produced.
- `--warnings-as-json`: write diagnostics as JSON to stderr.
- `--client-id-variable-name <name>`: override the APIM context variable used for resolved client IDs. Defaults to `oauthClientId`.
- `--emit-rate-limit-headers`: emit `X-RateLimit-Remaining-*` and `X-RateLimit-Limit-*` headers.
- `--source-ref <value>`: emit an operational source reference comment, typically a commit-pinned repository URL to the input JSON.
- `--source-revision <value>`: emit an operational source revision comment, typically the Git commit SHA used to generate the fragment.

At least one of `--output` or `--stdout` is required.

Exit codes:

- `0`: success.
- `1`: validation, compilation, or file IO failure.
- `2`: invalid CLI usage.

## Rate-Limit JSON v1

Top-level shape:

```json
{
  "$schema": "https://raw.githubusercontent.com/Altinn/apim-rate-limit-compiler/main/schemas/rate-limit-v1.schema.json",
  "version": 1,
  "name": "dialogporten",
  "enabled": true,
  "rules": []
}
```

Rule shape:

```json
{
  "id": "default",
  "enabled": true,
  "action": "limit",
  "match": {
    "methods": ["GET", "POST"],
    "pathMode": "prefix",
    "path": "/dialogporten",
    "caller": {
      "clientIds": ["client-a"],
      "scopes": ["dialogporten:read"]
    }
  },
  "keyMode": "client-id",
  "calls": 120,
  "renewalPeriod": 60
}
```

Supported values:

- `action`: `limit` or `exclude`. Defaults to `limit` when omitted.
- `match.methods`: `["*"]` or explicit methods: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`, `TRACE`.
- `match.pathMode`: `any`, `exact`, `prefix`.
- `match.caller.clientIds`: optional client IDs that the rule applies to.
- `match.caller.scopes`: optional OAuth scopes that the rule applies to.
- `keyMode`: `client-id`, `client-id-ip`.

`keyMode`, `calls`, and `renewalPeriod` are required for `limit` rules.

If both `match.caller.clientIds` and `match.caller.scopes` are present, both must match. Scope matching uses a padded string match against the bearer token's `scope` claim.

`exclude` rules are evaluated before all `limit` rules. If any enabled exclude rule matches, the generated fragment skips all rate limiting for that request:

```json
{
  "id": "health-exempt",
  "enabled": true,
  "action": "exclude",
  "match": {
    "methods": ["GET"],
    "pathMode": "exact",
    "path": "/dialogporten/health",
    "caller": {
      "scopes": ["monitoring:read"]
    }
  }
}
```

An exclude rule can also exempt a specific caller from all rate limiting:

```json
{
  "id": "foobar-exempt",
  "enabled": true,
  "action": "exclude",
  "match": {
    "methods": ["*"],
    "pathMode": "any",
    "caller": {
      "clientIds": ["foobar"]
    }
  }
}
```

The canonical JSON Schema for v1 is published at:

```text
https://raw.githubusercontent.com/Altinn/apim-rate-limit-compiler/main/schemas/rate-limit-v1.schema.json
```

Product repositories can reference that URL in the top-level `$schema` property to get editor and CI validation while keeping the file directly consumable by the compiler.

If top-level `enabled` is `false`, the compiler emits:

```xml
<fragment />
```

Disabled rules are ignored.

## Generated Policy Behavior

The output is APIM fragment XML rooted at `<fragment>`.

Generated fragments start with deterministic metadata comments:

- A warning that the fragment is compiler-generated and must not be edited manually.
- `Source-SHA256`, the SHA-256 hash of the JSON source content as compiled.
- `Compiler`, the compiler name and version.
- `Source`, when `--source-ref` is supplied.
- `Source-Revision`, when `--source-revision` is supplied.

The compiler does not emit timestamps. Prefer source revision and source hash for operational traceability without breaking deterministic output.

Generated fragments use `context.Variables["oauthClientId"]` as the client ID source by default. This variable name can be changed with `--client-id-variable-name`.

The fragment starts with a deterministic preamble that:

1. Leaves the configured client ID variable unchanged if it is already set and non-empty.
2. Reads the `Authorization` header otherwise.
3. Extracts the JWT payload from non-empty `Bearer` tokens.
4. Sets the configured client ID variable from the first `client_id` claim found in the payload.
5. Sets the configured client ID variable to an empty string when no client ID can be resolved.

The generated claim extractor is deliberately narrow and optimized for the expected token shape. It scans the decoded payload bytes for string-valued low-ASCII `client_id` and `scope` claims, but it does not validate the token and does not perform general JSON parsing.

When scope matching is used, the fragment decodes and scans the token once into an internal packed variable, then derives the configured client ID variable and `oauthScopes` from that value.

Rate limiting is skipped when the configured client ID variable is empty.

Generated rules use static `choose`/`when` blocks and `rate-limit-by-key` statements. Multiple matching rules emit multiple `rate-limit-by-key` statements, so burst and sustained limits can both apply.

Generated headers are stable. `Retry-After` is always configured. `X-RateLimit-*` headers are emitted only when `--emit-rate-limit-headers` is set:

- `Retry-After`
- `X-RateLimit-Remaining-{Name}-{RuleId}`
- `X-RateLimit-Limit-{Name}-{RuleId}`

Output is byte-for-byte deterministic for the same input and compiler version.

## Validation

Errors fail compilation:

- Invalid JSON.
- Unknown `version`.
- Unknown JSON properties.
- Duplicate rule IDs.
- Unsafe `name` or `id` characters. Only ASCII letters, digits, `-`, and `_` are allowed.
- Missing or invalid `calls`, `renewalPeriod`, `match.methods`, `match.pathMode`, or `keyMode` for `limit` rules.
- Missing or invalid `match.methods` or `match.pathMode` for `exclude` rules.
- `calls <= 0`.
- `renewalPeriod <= 0` or `renewalPeriod > 300`.
- `exact` or `prefix` path modes without `path`.
- Unsupported actions, methods, path modes, or key modes.
- Generated XML that cannot be parsed as XML.

Warnings do not fail compilation unless `--fail-on-warning` is set:

- More than 50 enabled rules in one configuration.
- Very high call limits.

## Development

Run tests:

```bash
dotnet test tests/ApimRateLimitCompiler.Tests/ApimRateLimitCompiler.Tests.csproj --no-restore -v minimal -nr:false
```

Run the local client ID extractor benchmark:

```bash
dotnet run -c Release --project benchmarks/ClientIdExtractorBench/ClientIdExtractorBench.csproj -- --iterations 3000000
```

Publish a Native AOT binary for a specific runtime identifier:

```bash
dotnet publish src/ApimRateLimitCompiler.Cli/ApimRateLimitCompiler.Cli.csproj \
  -c Release \
  -r linux-x64 \
  -p:PublishAot=true \
  -p:Version=1.2.3 \
  -p:InformationalVersion=1.2.3+local \
  -v minimal \
  -nr:false
```

For local test builds, use the helper script for the current platform:

```bash
./publish.sh
```

To stamp a local build with the same compiler version metadata shape used by release builds, pass a SemVer-like version:

```bash
./publish.sh 1.2.3
```

On Windows:

```bat
publish.bat 1.2.3
```

The scripts also accept `PUBLISH_VERSION=1.2.3` from the environment. If no version is supplied, the SDK default assembly version is used.

The published binary is written to:

```text
src/ApimRateLimitCompiler.Cli/bin/Release/net10.0/linux-x64/publish/
```

The release workflow currently builds `linux-x64`, `osx-arm64`, and `win-x64`.

## Release Workflow

Creating and publishing a GitHub Release runs `.github/workflows/release.yml`. The same workflow can also be run manually with `workflow_dispatch` by providing an existing release tag name.

The workflow:

- Derives the compiler version from the GitHub Release tag, accepting tags like `v1.2.3` or `1.2.3`.
- Restores the CLI for each release runtime identifier.
- Runs the test suite.
- Publishes the CLI as a Native AOT binary stamped with the release version.
- Prints `dotnet --info`, `file`, and `ldd` output to make release-run failures diagnosable.
- Smoke-tests the published binary against a fixture.
- Uploads release archives for `linux-x64`, `osx-arm64`, and `win-x64`.

Fragments generated by release binaries include the release version in the compiler metadata comment, for example:

```xml
<!-- Compiler: apim-rate-limit-compiler 1.2.3 -->
```

For downstream product repository usage, see [GitHub Actions with Bicep](examples/github-actions-bicep/README.md). That example downloads a pinned release asset, compiles reviewed rate-limit JSON, publishes XML/hash artifacts, and deploys an APIM `policyFragments` resource.

## Snapshot Tests

Valid fixtures live in:

```text
tests/ApimRateLimitCompiler.Tests/Fixtures/valid
```

Each valid `*.json` file has a matching `*.fragment.xml.snap`.

Invalid fixtures live in:

```text
tests/ApimRateLimitCompiler.Tests/Fixtures/invalid
```

Each invalid `*.json` file has a matching `*.diagnostics.snap`.

Snapshots are committed intentionally and should be reviewed like generated APIM artifacts.
