#!/usr/bin/env bash
# Fails if any .NET project in the repo resolves a NuGet package with a known vulnerability (direct or transitive).
# Run after a restore/build. CI runs it in the api job.
set -euo pipefail
cd "$(dirname "$0")/.."
found=0
for proj in api/Blueboard.slnx agents/*/*.csproj web/host/*.csproj dev/mock-msapi/*.csproj; do
  out="$(dotnet list "$proj" package --vulnerable --include-transitive 2>&1)" || { echo "$out"; exit 1; }
  if grep -q "has the following vulnerable packages" <<<"$out"; then
    echo "$out"
    found=1
  fi
done
if [[ "$found" == 1 ]]; then
  echo "vulnerable NuGet packages found (see above)" >&2
  exit 1
fi
echo "no vulnerable NuGet packages"
