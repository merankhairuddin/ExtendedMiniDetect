#!/bin/bash

MODULE_NAME="extended-minidetect"
SRC_FILE="${MODULE_NAME}.c"
OUT_DIR="build_output"
LOG_FILE="build.log"

mkdir -p "$OUT_DIR"
echo "[*] Starting multi-kernel build and deployment..." | tee "$LOG_FILE"

ls /lib/modules/ | while read -r KVER; do
    KBUILD="/lib/modules/$KVER/build"
    KDEST="/lib/modules/$KVER/extra"

    echo "[*] Processing kernel: $KVER" | tee -a "$LOG_FILE"

    if [ ! -d "$KBUILD" ]; then
        echo " [!] Skipped: Kernel headers not found for $KVER" | tee -a "$LOG_FILE"
        continue
    fi

    make clean > /dev/null 2>&1

    echo " [+] Building against headers: $KBUILD" | tee -a "$LOG_FILE"
    make -C "$KBUILD" M=$(pwd) EXTRA_CFLAGS="-std=gnu99" modules >> "$LOG_FILE" 2>&1

    if [ -f "${MODULE_NAME}.ko" ]; then
        mkdir -p "$OUT_DIR/$KVER"
        cp "${MODULE_NAME}.ko" "$OUT_DIR/$KVER/"
        echo "     [X] Build successful: $OUT_DIR/$KVER/${MODULE_NAME}.ko" | tee -a "$LOG_FILE"

        echo " [+] Installing module to $KDEST" | tee -a "$LOG_FILE"
        sudo mkdir -p "$KDEST"
        sudo cp "${MODULE_NAME}.ko" "$KDEST/"
        sudo depmod -a "$KVER"

        echo " [+] Testing modprobe for $KVER" | tee -a "$LOG_FILE"
        sudo modprobe -v "$MODULE_NAME" >> "$LOG_FILE" 2>&1

        echo "     [X] Module installed and tested for kernel $KVER" | tee -a "$LOG_FILE"
    else
        echo "     [X] Build failed for $KVER. See $LOG_FILE for details." | tee -a "$LOG_FILE"
    fi
done

echo "[*] Done. See $LOG_FILE for summary." | tee -a "$LOG_FILE"
