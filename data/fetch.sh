#!/usr/bin/env bash
# Fetches the pinned OTRF APT3 empire dataset (compound Windows simulation).
# Pinned to commit be0e82209deae630529fa2fa289dacf360b52351 for deterministic CI.
set -euo pipefail

DATA_DIR="$(cd "$(dirname "$0")" && pwd)"
DEST="$DATA_DIR/empire_apt3_2019-05-14223117.json"

if [ -f "$DEST" ]; then
  echo "Dataset already present: $DEST"
  exit 0
fi

COMMIT="be0e82209deae630529fa2fa289dacf360b52351"
URL="https://github.com/OTRF/Security-Datasets/raw/${COMMIT}/datasets/compound/windows/apt3/empire_apt3.tar.gz"

echo "Downloading APT3 dataset from OTRF/Security-Datasets @ ${COMMIT}..."
TMP="$DATA_DIR/empire_apt3.tar.gz"
curl -fsSL -o "$TMP" "$URL"

echo "Extracting..."
python3 -c "
import tarfile, os
with tarfile.open('$TMP', 'r:gz') as t:
    t.extractall('$DATA_DIR')
"

rm "$TMP"
echo "Dataset ready: $DEST"
