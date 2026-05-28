# GitHub Actions + Bicep Example

This example shows how a downstream product repository can use `apim-rate-limit-compiler` in GitHub Actions to compile reviewed rate-limit JSON into an Azure API Management policy fragment, upload the generated XML and hash as build artifacts, and deploy the fragment with Bicep.

The example targets an existing API Management instance. It does not create API Management, APIs, products, subscriptions, or attach the fragment to an API policy.

## Files

- `github-actions/apim-rate-limit-fragment.yml`: example GitHub Actions workflow.
- `infra/apim-policy-fragment.bicep`: deploy-only Bicep template for an existing API Management service.
- `rate-limits/dialogporten.json`: minimal sample compiler input.

## Copy Into A Product Repository

Copy the files you need into the product repository that owns the rate-limit JSON:

```text
.github/workflows/apim-rate-limit-fragment.yml
infra/apim-policy-fragment.bicep
rate-limits/dialogporten.json
```

Then edit the workflow constants near the top:

```yaml
env:
  APIM_RATE_LIMIT_COMPILER_VERSION: v0.3.0-alpha
  RATE_LIMIT_CONFIG_PATH: rate-limits/dialogporten.json
  FRAGMENT_OUTPUT_PATH: generated/apim-rate-limit-dialogporten.fragment.xml
  FRAGMENT_HASH_PATH: generated/apim-rate-limit-dialogporten.fragment.sha256
  BICEP_TEMPLATE_PATH: infra/apim-policy-fragment.bicep
```

Set `APIM_RATE_LIMIT_COMPILER_VERSION` to a reviewed, pinned release tag from this repository. The workflow downloads the matching `apim-rate-limit-compiler-linux-x64.tar.gz` release asset.

## GitHub Environment Configuration

The deploy job uses the `dev` GitHub environment by default. Create that environment in the product repository and configure these environment variables:

| Variable | Purpose |
| --- | --- |
| `AZURE_CLIENT_ID` | Client ID of the Microsoft Entra application or user-assigned managed identity used by GitHub OIDC. |
| `AZURE_TENANT_ID` | Tenant ID containing the federated credential. |
| `AZURE_SUBSCRIPTION_ID` | Subscription containing the API Management resource group. |
| `APIM_RESOURCE_GROUP` | Resource group of the existing API Management instance. |
| `APIM_SERVICE_NAME` | Existing API Management service name. |
| `APIM_POLICY_FRAGMENT_NAME` | Policy fragment resource name to create or update. |

No Azure client secret is required. Configure a federated identity credential for the GitHub repository, branch, and environment used by the workflow, then grant the identity least-privilege access to update policy fragments in the API Management resource group or service scope.

## Workflow Behavior

The workflow runs on:

- `pull_request`
- `push` to `main`
- `workflow_dispatch`

Every run compiles the configured JSON file and uploads two build artifacts:

- The generated APIM policy fragment XML.
- The SHA-256 hash of that generated XML.

Pull request runs stop there. Pushes to `main` and manual runs download the same artifact, sign in to Azure with GitHub OIDC, run `az deployment group what-if`, and then deploy with:

```bash
az deployment group create \
  --resource-group "$APIM_RESOURCE_GROUP" \
  --template-file "$BICEP_TEMPLATE_PATH" \
  --parameters @fragment.parameters.json
```

The compiler command includes `--source-ref` and `--source-revision`, so generated fragments contain commit-pinned operational metadata without embedding timestamps.

## Local Smoke Test

From a checkout of this repository, you can compile the sample input with the local CLI:

```bash
dotnet run --project src/ApimRateLimitCompiler.Cli -- \
  rate-limit \
  --input examples/github-actions-bicep/rate-limits/dialogporten.json \
  --output /tmp/apim-rate-limit-dialogporten.fragment.xml \
  --write-hash /tmp/apim-rate-limit-dialogporten.fragment.sha256 \
  --source-ref "https://github.com/Altinn/apim-rate-limit-compiler/blob/main/examples/github-actions-bicep/rate-limits/dialogporten.json" \
  --source-revision local \
  --fail-on-warning
```

The generated XML is deployable by the Bicep template as a `Microsoft.ApiManagement/service/policyFragments` child resource with `format` set to `rawxml`.
