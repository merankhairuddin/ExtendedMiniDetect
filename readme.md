# ExtendedMiniDetect - Rootkit and Credential Integrity Detection Kernel Module

`extendedminidetect` is a Linux kernel module designed to detect stealthy kernel-level rootkits and unauthorized modifications to process credentials. It uses a combination of kernel-space heuristics and LKRG-inspired mechanisms to monitor and report malicious activity.

---

## Features

### Rootkit Detection
- **Hidden Kernel Module Detection**: Detects modules that have been unlinked from `module_list`.
- **Syscall Hook Detection**: Compares syscall table entries against known good pointers.
- **Hidden Socket Detection**: Scans TCP hash tables and flags abnormal or hidden sockets.
- **Hidden Process Detection**: Identifies processes with suspicious flags (`0x10000000`) set.
- **TCP Seq Hook Check**: Detects hijacking of `tcp4_seq_show` used to hide entries in `/proc/net/tcp`.

### Credential Tampering Detection (LKRG-style)
- Tracks user-space processes and maintains a baseline of `cred` and `real_cred` structures.
- Uses `kprobes`/`kretprobes` on:
  - `wake_up_new_task`, `do_exit`
  - `prepare_creds`, `commit_creds`, `revert_creds`, and `security_bprm_committed_creds`
- Validation Flag:
  - **ON**: Triggers real-time credential integrity check.
  - **OFF**: Temporarily skips validation during legitimate changes.
- If tampering is detected:
  - Process is logged and killed (`SIGKILL`)
  - Flag corruption or pointer mismatch triggers alert

---

## Output Interface

- All findings are written to `/proc/minidetect_status`
- You can read it using:
  ```bash
  cat /proc/minidetect_status
  ```

---

## 🛠Building and Installing

Standard kernel module `Makefile`:

```bash
make                # Build minidetect.ko
sudo make install   # Copy module to kernel dir and run depmod
sudo modprobe extended_minidetect  # Load the module
```

To remove:

```bash
sudo rmmod extended_minidetect
sudo make uninstall
```

---

## Runtime Use

1. Load the module:
   ```bash
   sudo insmod extended-minidetect.ko
   ```

2. View detection output:
   ```bash
   cat /proc/minidetect_status
   ```

3. Remove the module:
   ```bash
   sudo rmmod extended_minidetect
   ```

---

## Warning

This tool interacts with low-level kernel structures. Use in production environments only if you understand the risks or are performing forensic analysis.

---

## 📄 License

GPLv2

---

Feel free to extend this project with:
- JSON output parser
- Automatic alert dispatch (via syslog, webhook, email)
- Full RMEDS integration with your incident response workflow
