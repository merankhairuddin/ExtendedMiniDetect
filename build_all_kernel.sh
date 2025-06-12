#!/bin/bash

MODULE_NAME="extended-minidetect"
SRC_FILE="${MODULE_NAME}.c"

# Optional: set output directory
OUT_DIR="build_output"

mkdir -p "$OUT_DIR"

echo "[*] Detected kernel headers:"
ls /lib/modules/ | while read -r KVER; do
    KBUILD="/lib/modules/$KVER/build"

    if [ -d "$KBUILD" ]; then
        echo " [+] Building for $KVER"
        make clean >/dev/null 2>&1

        make -C "$KBUILD" M=$(pwd) EXTRA_CFLAGS="-std=gnu99" modules

        if [ -f "${MODULE_NAME}.ko" ]; then
            mkdir -p "$OUT_DIR/$KVER"
            cp "${MODULE_NAME}.ko" "$OUT_DIR/$KVER/"
            echo "     ✅ Built and saved to $OUT_DIR/$KVER/"
        else
            echo "     ❌ Failed to build for $KVER"
        fi
    fi
done
