# Altinn APIM Policy Compiler

Deterministic .NET 10 CLI for compiling Altinn rate-limit JSON into Azure API Management policy fragment XML.

The compiler is intended for CI pipelines that keep rate-limit configuration as reviewed JSON and publish generated APIM `policyFragments` as build artifacts or deployment inputs.

## Projects

- `src/Altinn.ApimPolicyCompiler.Core`: JSON model, validation, diagnostics, hashing, and XML generation.
- `src/Altinn.ApimPolicyCompiler.Cli`: AOT-friendly command-line entrypoint.
- `tests/Altinn.ApimPolicyCompiler.Tests`: snapshot-focused tests for valid XML and invalid diagnostics.

## Requirements

- .NET SDK 10.0.100 or newer feature band.
- The repo includes `global.json` with `rollForward` set to `latestFeature`.

## Usage

Compile a rate-limit file to an APIM fragment:

```bash
dotnet run --project src/Altinn.ApimPolicyCompiler.Cli -- \
  rate-limit \
  --input rate-limits/dialogporten.json \
  --output generated/rate-limit-dialogporten.fragment.xml
```

The published native binary uses the same command shape:

```bash
altinn-apim-policy-compiler rate-limit \
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

At least one of `--output` or `--stdout` is required.

Exit codes:

- `0`: success.
- `1`: validation, compilation, or file IO failure.
- `2`: invalid CLI usage.

## Rate-Limit JSON v1

Top-level shape:

```json
{
  "$schema": "https://raw.githubusercontent.com/Altinn/altinn-apim-policy-compiler/main/schemas/rate-limit-v1.schema.json",
  "version": 1,
  "scope": "dialogporten",
  "enabled": true,
  "rules": []
}
```

Rule shape:

```json
{
  "id": "default",
  "enabled": true,
  "methods": ["GET", "POST"],
  "pathMode": "prefix",
  "path": "/dialogporten",
  "keyMode": "client-id",
  "calls": 120,
  "renewalPeriod": 60
}
```

Supported values:

- `methods`: `["*"]` or explicit methods: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`, `TRACE`.
- `pathMode`: `any`, `exact`, `prefix`.
- `keyMode`: `client-id`, `client-id-ip`, `client-id-claim`.

`keyClaimName` is required when `keyMode` is `client-id-claim`.

The canonical JSON Schema for v1 is published at:

```text
https://raw.githubusercontent.com/Altinn/altinn-apim-policy-compiler/main/schemas/rate-limit-v1.schema.json
```

Product repositories can reference that URL in the top-level `$schema` property to get editor and CI validation while keeping the file directly consumable by the compiler.

If top-level `enabled` is `false`, the compiler emits:

```xml
<fragment />
```

Disabled rules are ignored.

## Generated Policy Behavior

The output is APIM fragment XML rooted at `<fragment>`.

Generated fragments always use `context.Variables["oauthClientId"]` as the client ID source. The fragment starts with a deterministic preamble that:

1. Leaves `oauthClientId` unchanged if it is already set and non-empty.
2. Reads the `Authorization` header otherwise.
3. Parses non-empty `Bearer` tokens as JWT.
4. Sets `oauthClientId` from the JWT `client_id` claim when present.
5. Sets `oauthClientId` to an empty string when no client ID can be resolved.

Rate limiting is skipped when `oauthClientId` is empty.

Generated rules use static `choose`/`when` blocks and `rate-limit-by-key` statements. Multiple matching rules emit multiple `rate-limit-by-key` statements, so burst and sustained limits can both apply.

Generated headers are stable:

- `Retry-After`
- `X-RateLimit-Remaining-{Scope}-{RuleId}`
- `X-RateLimit-Limit-{Scope}-{RuleId}`

Output is byte-for-byte deterministic for the same input and compiler version.

## Validation

Errors fail compilation:

- Invalid JSON.
- Unknown `version`.
- Unknown JSON properties.
- Duplicate rule IDs.
- Unsafe `scope` or `id` characters. Only ASCII letters, digits, `-`, and `_` are allowed.
- Missing or invalid `calls`, `renewalPeriod`, `methods`, `pathMode`, or `keyMode`.
- `calls <= 0`.
- `renewalPeriod <= 0` or `renewalPeriod > 300`.
- `exact` or `prefix` path modes without `path`.
- `client-id-claim` without `keyClaimName`.
- Unsupported methods, path modes, or key modes.
- Generated XML that cannot be parsed as XML.

Warnings do not fail compilation unless `--fail-on-warning` is set:

- More than 50 enabled rules in one scope.
- Very high call limits.

## Development

Run tests:

```bash
dotnet test tests/Altinn.ApimPolicyCompiler.Tests/Altinn.ApimPolicyCompiler.Tests.csproj --no-restore -v minimal -nr:false
```

Publish a Native AOT binary for a specific runtime identifier:

```bash
dotnet publish src/Altinn.ApimPolicyCompiler.Cli/Altinn.ApimPolicyCompiler.Cli.csproj \
  -c Release \
  -r linux-x64 \
  -p:PublishAot=true \
  -v minimal \
  -nr:false
```

The published binary is written to:

```text
src/Altinn.ApimPolicyCompiler.Cli/bin/Release/net10.0/linux-x64/publish/
```

The release workflow currently builds `linux-x64`, `osx-arm64`, and `win-x64`.

## Release Workflow

Creating and publishing a GitHub Release runs `.github/workflows/release.yml`. The same workflow can also be run manually with `workflow_dispatch` by providing an existing release tag name.

The workflow:

- Restores the CLI for each release runtime identifier.
- Runs the test suite.
- Publishes the CLI as a Native AOT binary.
- Prints `dotnet --info`, `file`, and `ldd` output to make release-run failures diagnosable.
- Smoke-tests the published binary against a fixture.
- Uploads release archives for `linux-x64`, `osx-arm64`, and `win-x64`.

Downstream pipelines can download the matching release asset and run the binary directly:

```bash
tar -xzf altinn-apim-policy-compiler-linux-x64.tar.gz
./altinn-apim-policy-compiler rate-limit \
  --input rate-limits/dialogporten.json \
  --output generated/rate-limit-dialogporten.fragment.xml \
  --write-hash generated/rate-limit-dialogporten.sha256 \
  --fail-on-warning
```

## Snapshot Tests

Valid fixtures live in:

```text
tests/Altinn.ApimPolicyCompiler.Tests/Fixtures/valid
```

Each valid `*.json` file has a matching `*.fragment.xml.snap`.

Invalid fixtures live in:

```text
tests/Altinn.ApimPolicyCompiler.Tests/Fixtures/invalid
```

Each invalid `*.json` file has a matching `*.diagnostics.snap`.

Snapshots are committed intentionally and should be reviewed like generated APIM artifacts.
