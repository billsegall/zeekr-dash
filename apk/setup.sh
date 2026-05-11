#!/usr/bin/env bash
# Set up APK analysis workspace.
# Downloads jadx, extracts strings, runs full decompilation.
# Generated artifacts (src/, strings.txt, jadx.jar) are gitignored.

set -euo pipefail
cd "$(dirname "$0")"

JADX_VERSION="1.5.1"
JADX_JAR="jadx.jar"
APK="../zeekr_base.apk"
SRC_DIR="src"

# ── 1. Extract strings (fast, pure Python) ──────────────────────────────────
echo "==> Extracting DEX strings..."
python3 extract_strings.py "$APK"

# ── 2. Download jadx ─────────────────────────────────────────────────────────
if [ ! -f "$JADX_JAR" ]; then
    echo "==> Downloading jadx ${JADX_VERSION}..."
    curl -L \
        "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
        -o jadx-dist.zip
    # Extract just the lib/jadx-all.jar (the fat jar with all deps)
    unzip -jo jadx-dist.zip "lib/jadx-${JADX_VERSION}-all.jar" -d .
    mv "jadx-${JADX_VERSION}-all.jar" "$JADX_JAR"
    rm jadx-dist.zip
    echo "    jadx downloaded → $JADX_JAR"
else
    echo "==> jadx already present, skipping download"
fi

# ── 3. Decompile APK ─────────────────────────────────────────────────────────
echo "==> Decompiling $APK with jadx (this takes a few minutes)..."
java -cp "$JADX_JAR" jadx.cli.JadxCLI \
    --deobf \
    --show-bad-code \
    --threads-count 4 \
    --output-dir "$SRC_DIR" \
    "$APK"
echo "==> Done. Decompiled source in apk/$SRC_DIR/"
