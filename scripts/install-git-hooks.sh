#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "${ROOT}"

chmod +x scripts/betterleaks-scan.sh scripts/hooks/pre-push

git config core.hooksPath scripts/hooks

echo "Installed git hooks from scripts/hooks (core.hooksPath=scripts/hooks)."
echo "Pre-push runs BetterLeaks on commits being pushed."
echo "Manual scan: scripts/betterleaks-scan.sh"
