#!/usr/bin/env sh
set -eu

project="src/ApimRateLimitCompiler.Cli/ApimRateLimitCompiler.Cli.csproj"
framework="net10.0"
configuration="Release"
executable_name="apim-rate-limit-compiler"
publish_version="${PUBLISH_VERSION:-${1:-}}"

os="$(uname -s)"
arch="$(uname -m)"

case "$os" in
  Darwin)
    case "$arch" in
      arm64|aarch64) rid="osx-arm64" ;;
      x86_64|amd64) rid="osx-x64" ;;
      *) echo "Unsupported macOS architecture: $arch" >&2; exit 2 ;;
    esac
    ;;
  Linux)
    case "$arch" in
      arm64|aarch64) rid="linux-arm64" ;;
      x86_64|amd64) rid="linux-x64" ;;
      *) echo "Unsupported Linux architecture: $arch" >&2; exit 2 ;;
    esac
    ;;
  *)
    echo "Unsupported OS: $os" >&2
    exit 2
    ;;
esac

version_args=""
if [ -n "$publish_version" ]; then
  case "$publish_version" in
    v*) publish_version="${publish_version#v}" ;;
  esac

  if ! printf '%s\n' "$publish_version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$'; then
    echo "Version must be SemVer-like, for example v1.2.3 or 1.2.3-preview.1." >&2
    exit 2
  fi

  version_args="-p:Version=$publish_version -p:InformationalVersion=$publish_version+local"
fi

# shellcheck disable=SC2086
dotnet publish "$project" \
  -c "$configuration" \
  -r "$rid" \
  -p:PublishAot=true \
  $version_args \
  -v minimal \
  -nr:false

binary_path="src/ApimRateLimitCompiler.Cli/bin/$configuration/$framework/$rid/publish/$executable_name"

echo
echo "Published binary:"
echo "$binary_path"

if [ -n "$publish_version" ]; then
  echo "Version: $publish_version"
fi
