# ContainerKiller — Safety Audit

Each exploit function is classified by its effect on the host system.

## Key

| Column | Meaning |
|--------|---------|
| **Read-only?** | Only reads files / queries APIs / prints info — zero side effects |
| **Host write?** | Writes data to the host (files, kernel params, container create) |
| **Cleans up?** | Restores previous state and removes temp files |
| **Persistent state?** | Anything left behind after CK exits |

---

## All exploits, by category

### Category 1 — Runtime Misconfig

| ID | Read-only? | Host write? | Cleans up? | Persistent state? | Notes |
|----|-----------|-------------|------------|-------------------|-------|
| 1.1 cgroup release_agent | **No** | Yes — release_agent + triggers host shell as root | **Partial** — cgroup mount not unmounted, release_agent not restored | **Yes** — stale mount + dangling kernel value | Most dangerous; modifies host kernel state and executes payload as host root. Do NOT run outside a dedicated lab VM. |
| 1.3 /dev/mem | **Yes** | No | N/A | No | Safe. Reads kernel memory via dd/grep (read-only). |
| 1.4 cgroup v2 eBPF device bypass | **No** | Yes — detaches BPF_CGROUP_DEVICE programs (kernel state) | **Partial** — fail-closed restore; runtime may have reaped a detached program (then `docker compose restart` required) | No (after restart) | Detach/attach on the container cgroup only; restore verified by re-query. |

### Category 2 — Capabilities

| ID | Read-only? | Host write? | Cleans up? | Persistent state? | Notes |
|----|-----------|-------------|------------|-------------------|-------|
| 2.1 CAP_SYS_ADMIN | Varies | Delegates to block device check or prints info | N/A | No (delegated) | |
| 2.2 CAP_SYS_PTRACE | **Yes** | No | N/A | No | Informational only. Does NOT actually ptrace. |
| 2.3 CAP_SYS_MODULE | **Yes** | No | N/A | No | Informational only. Does NOT load modules. |
| 2.4 CAP_NET_ADMIN | **Yes** | No | N/A | No | Informational only. |
| 2.7 CAP_SYS_RAWIO | **Yes** | No | N/A | No | Checks device existence only. |
| 2.8 CAP_SYS_BOOT | **Yes** | No | N/A | No | Does NOT kexec. Prints info only. |
| 2.9 CAP_DAC_READ_SEARCH | **Yes** | No | N/A | No | Informational only. |
| 2.10 CAP_SYS_CHROOT | **No** | Yes — proof markers on host /tmp via chroot+dirfd | Yes — ck_mount_cleanup in all paths | No | Writes + verifies + removes markers. Safe PoC. |

### Category 3 — Namespaces

| ID | Read-only? | Host write? | Cleans up? | Persistent state? | Notes |
|----|-----------|-------------|------------|-------------------|-------|
| 3.1 host PID nsenter | **Yes** | No | N/A | No | Enters all host namespaces but only runs `id`. |
| 3.2 host net | **Yes** | No | N/A | No | Reads `ip addr` / `ss`. |
| 3.3 host IPC | **Yes** | No | N/A | No | Reads `ipcs`. |
| 3.4 mount breakout | **No** | No (contained in new ns) | Yes — namespace dies with subprocess | No | Bind mount is transient; new mount namespace destroyed on exit. |

### Category 4 — Filesystem

| ID | Read-only? | Host write? | Cleans up? | Persistent state? | Notes |
|----|-----------|-------------|------------|-------------------|-------|
| 4.1 docker socket | **No** | Yes — creates privileged container, pulls Alpine image | Container deleted, **image stays** | **Yes** — image in Docker store | Audit trail + image pull remain. |
| 4.2 mount root | **Yes** | No | N/A | No | Reads shadow from existing mount. |
| 4.3 core_pattern | **No** | Yes — overwrites host crash handler temporarily | Restores core_pattern, removes payload | No | Fragile: if killed mid-exec, core_pattern stays modified. Also kills a local `sleep` with SIGSEGV (container-only). |
| 4.4 uevent_helper | **No** | Yes — overwrites host uevent handler temporarily | Restores helper, **but temp files leak** | **Yes** — `/tmp/ck_uevent`, `/tmp/ck_pwned` | Cleanup bug. |
| 4.5 sysrq-trigger | **Yes** (standalone) | No (standalone) / writes safe `h` key with `CK_FORCE=1` | N/A | No | Only auto-triggered with `CK_FORCE=1`, otherwise prints warning. `h` key prints help — no reboot/crash. |
| 4.6 /proc/1/root | **Yes** | No | N/A | No | Stat checks only; does not actually write. |
| 4.9 bind mount /etc/passwd | **Yes** | No | N/A | No | Suggests append; does NOT write. |
| 4.10 nsenter direct | **Yes** | No | N/A | No | Suggests command; does NOT run it. |
| 4.11 shared mount | **No** | No (container mount ns only) | **No** — propagation never reverted | **Yes** — `/tmp` stays shared until container restart | Changes container-level mount propagation permanently. |

### Category 5 — Docker API

| ID | Read-only? | Host write? | Cleans up? | Persistent state? | Notes |
|----|-----------|-------------|------------|-------------------|-------|
| 5.2 docker TCP API | **Yes** | No | N/A | No | GET containers/json only. Does NOT create containers. |

### Category 8 — Devices

| ID | Read-only? | Host write? | Cleans up? | Persistent state? | Notes |
|----|-----------|-------------|------------|-------------------|-------|
| 8.4 block devices | **Yes** | No | N/A | No | `fdisk -l` only. |

### Category 9 — Image & Build

| ID | Read-only? | Host write? | Cleans up? | Persistent state? | Notes |
|----|-----------|-------------|------------|-------------------|-------|

### Category 10 — Secrets

| ID | Read-only? | Host write? | Cleans up? | Persistent state? | Notes |
|----|-----------|-------------|------------|-------------------|-------|

### Category 11 — Supply Chain

| ID | Read-only? | Host write? | Cleans up? | Persistent state? | Notes |
|----|-----------|-------------|------------|-------------------|-------|
| 11.1 LD_PRELOAD | **Yes** | No | N/A | No | Suggests how-to; creates nothing. |

### Category 12 — Kubernetes

| ID | Read-only? | Host write? | Cleans up? | Persistent state? | Notes |
|----|-----------|-------------|------------|-------------------|-------|
| 12.1 privileged pod | **No** | Yes — proof markers via nsenter + /proc/1/root | Yes — both vectors clean up | No | Write-verify-delete cycle. Safe PoC. |
| 12.2 hostPath mount | **No** | Yes — proof markers via mount | Yes — ck_mount_cleanup in all paths | No | Same pattern as 12.1. |
| 12.3 hostPID+Net | Varies | Yes if privileged+nsenter, else read-only | Yes when writes happen | No | Observation mode is safe; escape mode cleans up. |

---

## Summary

| Exploits | Count |
|----------|-------|
| **Read-only / informational** (zero side effects) | 30 |
| **Write host state — cleans up properly** | 6 (2.10, 3.4, 4.5 with CK_FORCE, 8.3, 12.1, 12.2) |
| **Write host state — cleanup BUG (artifact left)** | 5 (1.1, 4.4, 4.8, 4.11, 5.4) |
| **Write host state — container/image created** | 1 (4.1) |
| **Write host state — fragile restore** | 1 (4.3 — kills container process; if interrupted, core_pattern stays) |

## Known cleanup bugs

1. **1.1** — cgroup mount not unmounted; release_agent not restored to previous value.
2. **4.4** — `/tmp/ck_uevent` and `/tmp/ck_pwned` never removed from container.
3. **4.8** — `ck_overlay_test` file permanently written to host overlay upperdir.
4. **4.11** — mount propagation of `/tmp` changed to shared, never reverted (persists until container restart).
5. **5.4** — Container created on host Docker daemon, never deleted.
6. **4.1** — Alpine image pulled and cached on host Docker store (persistent).
7. **4.3** — If CK is killed/crashes during execution, core_pattern is NOT restored (host crash handler left modified).

## Running safely

To run CK as a **zero-side-effect auditor** on a production system:

```bash
# Scan only (no exploits run at all)
sh containerkiller.sh scan

# Run only read-only exploits (skip the 10 that write)
sh containerkiller.sh exploit 1.3 2.2 2.3 2.4 2.7 2.8 2.9 \
                             3.1 3.2 3.3 \
                             4.2 4.5 4.6 4.9 4.10 \
                             5.2 5.5 \
                             8.1 8.2 8.4 \
                             9.1 9.2 \
                             10.1 10.2 10.3 10.4 \
                             11.1 \
                             12.4
```

Never run `sh containerkiller.sh all` or `sh containerkiller.sh exploit` without first reviewing the above.
