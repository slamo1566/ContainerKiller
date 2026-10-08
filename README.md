<br><br>

# ContainerKiller

### 🥷 Container Sandbox Evasion & Host Compromise Tool

**Pure POSIX shell • Zero dependencies • No Python • Runs anywhere**

Upload into ANY container and run to detect vulnerabilities, report protections, and automatically escape to the host.

<br>

<p>
<!-- Status badges -->
<img src="https://img.shields.io/badge/Techniques-48-red?style=for-the-badge&logo=terminal&logoColor=white" alt="48 Techniques">
<img src="https://img.shields.io/badge/Shell-POSIX-brightgreen?style=for-the-badge&logo=gnubash&logoColor=white" alt="POSIX Shell">
<img src="https://img.shields.io/badge/Dependencies-Zero-000000?style=for-the-badge&logo=minimalism&logoColor=white" alt="Zero Dependencies">
<img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge&logo=opensourceinitiative&logoColor=white" alt="MIT License">
</p>

<p>
<!-- Tech badges -->
<img src="https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker">
<img src="https://img.shields.io/badge/Kubernetes-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white" alt="Kubernetes">
<img src="https://img.shields.io/badge/Linux-Kernel-FCC624?style=for-the-badge&logo=linux&logoColor=black" alt="Linux Kernel">
<img src="https://img.shields.io/badge/Containerd-000000?style=for-the-badge&logo=containerd&logoColor=white" alt="Containerd">
</p>

<p>
<!-- Red Team / Offensive badges -->
<img src="https://img.shields.io/badge/🔴_Red_Team-Sandbox_Evasion-DC143C?style=for-the-badge&logo=metasploit&logoColor=white" alt="Red Team">
<img src="https://img.shields.io/badge/🐳_Container-Escape-0db7ed?style=for-the-badge&logo=containerd&logoColor=white" alt="Container Escape">
<img src="https://img.shields.io/badge/🎯_Pentest-Privilege_Escalation-8B0000?style=for-the-badge&logo=burpsuite&logoColor=white" alt="Pentest">
<img src="https://img.shields.io/badge/🥷_Stealth-No_Trace-1a1a2e?style=for-the-badge&logo=ninja&logoColor=white" alt="Stealth">
</p>


---

## ⚡ Quick Start

```bash
# Upload to a container (from host)
docker cp containerkiller.sh <container_id>:/tmp/
docker exec -it <container_id> sh /tmp/containerkiller.sh all

# Or directly inside the container
sh containerkiller.sh all
```

## 🎮 Usage

| Command | Description |
|---------|-------------|
| `sh containerkiller.sh scan` | Scan: env + vulnerabilities + protections + target versions |
| `sh containerkiller.sh exploit` | Scan + try all applicable escapes |
| `sh containerkiller.sh exploit 1.1` | Run specific technique only |
| `sh containerkiller.sh all` | Scan + exploit + report |
| `sh containerkiller.sh list` | List all 48 techniques |

## 📊 What It Reports

- **VULNERABILITIES** — dangerous conditions found (privileged mode, caps, socket, host mounts…)
- **PROTECTIONS PRESENT** — hardening in place (NoNewPrivs, read-only rootfs, SELinux, kptr/dmesg restrict, userns limits) + assessment
- **TARGET VERSIONS** — kernel/distro/runtime versions as intel for you to cross-check public exploits yourself
- **Applicable techniques** with per-technique SUCCESS/FAILED verdicts

## 🎯 Scope

CK exploits **misconfigurations** (privileged, capabilities, mounts, docker API, secrets…).  
Kernel/OCI runtime CVEs (Dirty Pipe, runC, etc.) are **not** exploited — they are exercised manually in a dedicated vulnerable VM.

## 🗂️ Supported Techniques (48)

| Category | IDs | Techniques |
|----------|-----|------------|
| **Runtime Misconfig** | 1.1, 1.3, 1.4 | cgroup release agent (v1), /dev/mem, cgroup v2 eBPF device bypass |
| **Capabilities** | 2.1–2.10 | SYS_ADMIN, PTRACE, MODULE, NET_ADMIN, DAC_OVERRIDE, RAWIO, BOOT, DAC_READ_SEARCH, CHROOT… |
| **Namespaces** | 3.1–3.4 | host PID nsenter, host net, host IPC, mount breakout |
| **Filesystem** | 4.1–4.11 | docker socket, root mount, core_pattern, uevent_helper, sysrq, /proc/1/root… |
| **Docker API** | 5.2 | TCP API |
| **Devices** | 8.4 | block devices |
| **Supply Chain** | 11.1 | LD_PRELOAD hijack |
| **Kubernetes** | 12.1–12.3 | privileged pod, hostPath, hostPID |

## 🔒 Escape Contract (Detect → Exploit → Verify → Restore)

Every real escape follows a strict contract:

1. **Detect** — identify the vulnerability
2. **Exploit** — write a unique marker (`ck_$$_$(date +%s)`) on the host
3. **Verify** — prove the marker is readable from host side, **not** visible from container, and host mount/PID namespace differs
4. **Restore** — delete the marker. No leftover host state, no false positives.

Marker helpers: `ck_marker`, `ck_nsenter_marker/verify/cleanup`, `ck_mount_marker/verify/cleanup`.

## 🆕 Recent Highlights

- **12.1–12.3 rewritten as real escapes** — privileged pod `nsenter -t 1 -a` to node init (marker proof), hostPath marker proof, hostPID honest split (observation vs real escape)
- **2.10 CAP_SYS_CHROOT** — chroot into mounted host root with marker proof; dirfd jail-break fallback
- **4.5 sysrq gated by `CK_FORCE=1`** — never auto-triggered in `all` mode; safe `h` key only
- **nsenter verify uses mount-namespace diff** — reliable under `hostNetwork`
- **Host-mirror proc/sys detection** — probes `/host/proc`, `/mnt/proc`, `/run/host/proc`, `/hostroot/proc` for labs with non-default mount paths
- **`/proc/1/root` accuracy** — real traversal check, no false SUCCESS when Yama blocks access
- **Host hygiene** — restores `core_pattern`/`uevent_helper` after verifying write

## 🤝 Companion Project: EscapeHatch

For **hands-on learning labs** that teach these techniques:

**[EscapeHatch](https://github.com/slamo1566/EscapeHatch)** — 28 reproducible labs covering Docker, capabilities, namespaces, filesystem, and Kubernetes escapes.

```bash
git clone https://github.com/slamo1566/EscapeHatch.git
cd EscapeHatch && make install
python EscapeHatch.py up 1.1
```

EscapeHatch's `real-cluster.sh` automatically injects ContainerKiller into K8s lab pods for verification.

## ⚠️ Safety

**Read [SAFETY.md](SAFETY.md)** before running on production systems.

| Exploit Type | Count |
|--------------|-------|
| Read-only / informational (zero side effects) | 30 |
| Write host state — cleans up properly | 6 |
| Write host state — cleanup bugs / artifacts | 5 |
| Write host state — container/image created | 1 |
| Write host state — fragile restore | 1 |

```bash
# Scan only (zero side effects)
sh containerkiller.sh scan

# Run only read-only exploits
sh containerkiller.sh exploit 1.3 2.2 2.3 2.4 2.7 2.8 2.9 \
                             3.1 3.2 3.3 \
                             4.2 4.5 4.6 4.9 4.10 \
                             5.2 8.4 11.1
```

## 📜 License

MIT — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Built for Red Teamers, Pentesters, and Container Security Researchers**

[⭐ Star this repo](https://github.com/slamo1566/Containerkiller) • [🐛 Report Bug](https://github.com/slamo1566/Containerkiller/issues) • [💡 Request Feature](https://github.com/slamo1566/Containerkiller/issues) • [🔗 EscapeHatch Labs](https://github.com/slamo1566/EscapeHatch)

</div>
