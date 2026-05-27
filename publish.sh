#!/usr/bin/env sh
set -eu

project="src/ApimPolicyCompiler.Cli/ApimPolicyCompiler.Cli.csproj"
framework="net10.0"
configuration="Release"
executable_name="apim-policy-compiler"

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

dotnet publish "$project" \
  -c "$configuration" \
  -r "$rid" \
  -p:PublishAot=true \
  -v minimal \
  -nr:false

binary_path="src/ApimPolicyCompiler.Cli/bin/$configuration/$framework/$rid/publish/$executable_name"

echo
echo "Published binary:"
echo "$binary_path"
