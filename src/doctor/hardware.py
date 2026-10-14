"""What this computer is made of, as plain data: processor, memory sticks, drives, graphics cards, monitors, board and
firmware, battery, network adapters. Gathering only (sysfs, udev, lscpu, lsblk, lspci, nvidia-smi; smartctl with sudo);
sysinfo.py turns it into words. Everything works without root except drive wear and hours."""
import glob, json, os, re, shlex, time

from .core import read

CACHE_DAYS = 7   # hardware rarely changes: the assistant reuses the last collection for this long


def cached(ctx, path, max_days=CACHE_DAYS):
    """The last collection saved at `path` while it's fresh, else a new one (saved there). About half a second."""
    try:
        with open(path) as fh:
            facts = json.load(fh)
        if time.time() - facts.get("time", 0) < max_days * 86400:
            return facts
    except (OSError, ValueError):
        pass
    return save(collect(ctx), path)


def save(facts, path):
    try:
        with open(path, "w") as fh:
            json.dump(facts, fh)
    except OSError:
        pass
    return facts


def _sys(path):
    return read(path).strip()


def _int(s, default=0):
    try:
        return int(str(s).strip())
    except (TypeError, ValueError):
        return default


def _float(s, default=None):
    try:
        return float(str(s).strip())
    except (TypeError, ValueError):
        return default


# ---------- pure parsers (tested on captured output) ----------

def parse_lscpu(text):
    """`lscpu` (LC_ALL=C) -> {field: value}."""
    out = {}
    for line in text.splitlines():
        k, sep, v = line.partition(":")
        if sep and k.strip() and k.strip() not in out:
            out[k.strip()] = v.strip()
    return out


def parse_udev_memory(text):
    """`udevadm info /sys/devices/virtual/dmi/id` -> (slots, max_capacity, [stick]). Sticks with no size are empty slots."""
    props = dict(re.findall(r"^E: (MEMORY_\w+)=(.*)$", text, re.M))
    sticks = {}
    for key, val in props.items():
        m = re.match(r"MEMORY_DEVICE_(\d+)_(\w+)", key)
        if m:
            sticks.setdefault(int(m.group(1)), {})[m.group(2)] = val.strip()
    slots = _int(props.get("MEMORY_ARRAY_NUM_DEVICES"), len(sticks))
    dimms = []
    for n in sorted(sticks):
        s = sticks[n]
        size = _int(s.get("SIZE"))
        if not size or s.get("PRESENT") == "0":
            continue
        dimms.append({"size": size, "type": s.get("TYPE", ""), "speed": _int(s.get("SPEED_MTS")),
                      "configured": _int(s.get("CONFIGURED_SPEED_MTS")), "maker": s.get("MANUFACTURER", ""),
                      "part": s.get("PART_NUMBER", "").strip(), "slot": s.get("LOCATOR", ""),
                      "form": s.get("FORM_FACTOR", ""), "ecc": _int(s.get("TOTAL_WIDTH")) > _int(s.get("DATA_WIDTH"), 64)})
    return max(slots, len(dimms)), _int(props.get("MEMORY_ARRAY_MAX_CAPACITY")), dimms


def parse_lspci_vmm(text):
    """`lspci -vmm -s ADDR` -> {Vendor, Device, SVendor, ...}."""
    return {k: v.strip() for k, v in re.findall(r"^(\w+):\s*(.*)$", text, re.M)}


def marketing_name(device):
    """'GA102 [GeForce RTX 3090 Ti]' -> 'GeForce RTX 3090 Ti' (the name on the box, not the chip codename)."""
    m = re.search(r"\[([^\]]+)\]\s*$", device or "")
    return m.group(1) if m else (device or "")


def pcie_gen(speed):
    """'8.0 GT/s PCIe' -> 3."""
    gts = _float((speed or "").split()[0] if speed else None)
    return {2.5: 1, 5.0: 2, 8.0: 3, 16.0: 4, 32.0: 5, 64.0: 6}.get(gts) if gts else None


def parse_edid(data):
    """A monitor's EDID bytes -> {"name", "max_hz"} (its own name, and the fastest refresh it says it takes)."""
    out = {"name": "", "max_hz": None}
    if len(data) < 128 or data[:8] != b"\x00\xff\xff\xff\xff\xff\xff\x00":
        return out
    for off in (54, 72, 90, 108):
        b = data[off:off + 18]
        if b[:3] != b"\x00\x00\x00":
            continue
        if b[3] == 0xFC:
            out["name"] = b[5:18].split(b"\n")[0].decode("ascii", "replace").strip()
        elif b[3] == 0xFD:
            out["max_hz"] = b[6] + (255 if b[4] & 0x02 else 0)
    return out


def parse_nvidia_bar1(text):
    """`nvidia-smi -q -d MEMORY` -> {bus_id: BAR1 size in MiB}. 256 MiB means Resizable BAR is off."""
    out, bus = {}, None
    for line in text.splitlines():
        m = re.match(r"^GPU ([0-9A-Fa-f:.]+)", line)
        if m:
            bus = m.group(1).lower()[-12:]
        elif "BAR1 Memory Usage" in line:
            out[bus] = "pending"
        elif out.get(bus) == "pending" and line.strip().startswith("Total"):
            out[bus] = _int(re.sub(r"\D", "", line))
    return {k: v for k, v in out.items() if isinstance(v, int)}


# ---------- gathering ----------

def collect(ctx):
    facts = {"time": time.time(), "sudo": bool(ctx.sudo)}
    for part, fn in (("os", _os), ("board", _board), ("cpu", _cpu), ("memory", _memory), ("disks", _disks),
                     ("gpus", _gpus), ("displays", _displays), ("battery", _battery), ("net", _net)):
        try:
            facts[part] = fn(ctx)
        except Exception as e:   # one unreadable part must never sink the rest
            facts[part] = {"error": f"{type(e).__name__}: {e}"} if part in ("os", "board", "cpu", "memory") else []
    return facts


def _os(ctx):
    rel = dict(re.findall(r'^(\w+)="?([^"\n]*)"?$', read("/etc/os-release"), re.M))
    return {"name": rel.get("PRETTY_NAME", "Linux"), "kernel": os.uname().release, "arch": os.uname().machine,
            "host": os.uname().nodename, "uptime": _float(read("/proc/uptime").split()[0] if read("/proc/uptime") else 0, 0),
            "session": os.environ.get("XDG_SESSION_TYPE", ""), "desktop": os.environ.get("XDG_CURRENT_DESKTOP", ""),
            "virt": ctx.run("systemd-detect-virt 2>/dev/null").strip()}


def _board(ctx):
    dmi = lambda f: _sys(f"/sys/class/dmi/id/{f}")
    sb = None
    for f in glob.glob("/sys/firmware/efi/efivars/SecureBoot-*"):
        try:
            with open(f, "rb") as fh:
                sb = fh.read()[-1:] == b"\x01"
        except OSError:
            pass
    tpm = _sys("/sys/class/tpm/tpm0/tpm_version_major") or ("1.2" if os.path.exists("/sys/class/tpm/tpm0") else "")
    return {"vendor": dmi("sys_vendor"), "product": dmi("product_name"), "family": dmi("product_family"),
            "version": dmi("product_version"), "board_vendor": dmi("board_vendor"), "board": dmi("board_name"),
            "bios_vendor": dmi("bios_vendor"), "bios_version": dmi("bios_version"), "bios_date": dmi("bios_date"),
            "chassis": _int(dmi("chassis_type")), "uefi": os.path.isdir("/sys/firmware/efi"), "secure_boot": sb, "tpm": tpm}


def _cpu(ctx):
    info = parse_lscpu(ctx.run("lscpu"))
    flags = set(info.get("Flags", "").split())
    cpuinfo = read("/proc/cpuinfo")
    if not flags:
        m = re.search(r"^(?:flags|Features)\s*:\s*(.*)$", cpuinfo, re.M)
        flags = set(m.group(1).split()) if m else set()
    cores = _int(info.get("Core(s) per socket"), 0) * max(_int(info.get("Socket(s)"), 1), 1)
    threads = _int(info.get("CPU(s)"), os.cpu_count() or 1)
    freq = "/sys/devices/system/cpu/cpu0/cpufreq/"
    cur = [_int(read(f)) for f in glob.glob("/sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq")]
    hybrid = {k: len(_cpulist(_sys(f"/sys/devices/{d}/cpus"))) for k, d in (("p", "cpu_core"), ("e", "cpu_atom"))
              if os.path.exists(f"/sys/devices/{d}/cpus")}
    micro = re.search(r"^microcode\s*:\s*(\S+)", cpuinfo, re.M)
    return {"model": re.sub(r"\s+", " ", info.get("Model name", "") or "").strip(), "vendor": info.get("Vendor ID", ""),
            "arch": info.get("Architecture", ""), "cores": cores or threads, "threads": threads,
            "sockets": max(_int(info.get("Socket(s)"), 1), 1),
            "max_mhz": _float(info.get("CPU max MHz")) or _int(_sys(freq + "cpuinfo_max_freq")) / 1000 or None,
            "min_mhz": _float(info.get("CPU min MHz")), "base_mhz": _int(_sys(freq + "base_frequency")) / 1000 or None,
            "cur_mhz": [min(cur) / 1000, max(cur) / 1000] if cur else None,
            "l2": info.get("L2 cache", ""), "l3": info.get("L3 cache", ""), "virt": info.get("Virtualization", ""),
            "flags": sorted(flags & {"avx", "avx2", "avx512f", "avx_vnni", "amx_tile", "aes", "sha_ni", "vmx", "svm",
                                     "hypervisor", "ht", "lm", "sse4_2"}),
            "governor": _sys(freq + "scaling_governor"), "epp": _sys(freq + "energy_performance_preference"),
            "driver": _sys(freq + "scaling_driver"), "microcode": micro.group(1) if micro else "",
            "smt": _sys("/sys/devices/system/cpu/smt/control"), "p_cores": hybrid.get("p"), "e_cores": hybrid.get("e"),
            "kvm": os.path.exists("/dev/kvm")}


def _cpulist(s):
    out = []
    for part in s.split(","):
        a, _, b = part.partition("-")
        if a.strip().isdigit():
            out += list(range(int(a), int(b or a) + 1))
    return out


def _memory(ctx):
    m = {k: _int(v.split()[0]) * 1024 for k, v in re.findall(r"^(\w+):\s+(.*)$", read("/proc/meminfo"), re.M)}
    slots, cap, dimms = parse_udev_memory(ctx.run("udevadm info /sys/devices/virtual/dmi/id 2>/dev/null"))
    zram = sum(_int(_sys(f)) for f in glob.glob("/sys/block/zram*/disksize"))
    return {"total": m.get("MemTotal", 0), "available": m.get("MemAvailable", 0), "swap_total": m.get("SwapTotal", 0),
            "swap_used": m.get("SwapTotal", 0) - m.get("SwapFree", 0), "zram": zram,
            "slots": slots, "max_capacity": cap, "dimms": dimms}


def _pci_of(sys_path):
    """The PCI device a block/drm/net device sits on, and its link: (address, {gen, width, max_gen, max_width, slot_gen})."""
    dev = os.path.realpath(sys_path)
    while dev != "/" and not re.fullmatch(r"[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.\d", os.path.basename(dev)):
        dev = os.path.dirname(dev)
    if dev == "/":
        return None, None
    up = os.path.dirname(dev)
    link = {"gen": pcie_gen(_sys(f"{dev}/current_link_speed")), "width": _int(_sys(f"{dev}/current_link_width")) or None,
            "max_gen": pcie_gen(_sys(f"{dev}/max_link_speed")), "max_width": _int(_sys(f"{dev}/max_link_width")) or None,
            "slot_gen": pcie_gen(_sys(f"{up}/max_link_speed")), "slot_width": _int(_sys(f"{up}/max_link_width")) or None}
    return os.path.basename(dev), link if link["max_gen"] else None


def _disks(ctx):
    try:
        tree = json.loads(ctx.run("lsblk -J -b -e 1,7,11 -o NAME,SIZE,ROTA,TRAN,MODEL,TYPE,RM,MOUNTPOINT") or "{}")
    except ValueError:
        return []
    root_src = ctx.run("findmnt -n -o SOURCE /").strip()
    trim = ctx.run("systemctl is-enabled fstrim.timer 2>/dev/null").strip()
    disks = []
    for d in tree.get("blockdevices", []):
        if d.get("type") != "disk" or not d.get("size") or d["name"].startswith(("zram", "ram")):
            continue
        mounts = []

        def walk(node):
            if node.get("mountpoint") and node["mountpoint"].startswith("/") and not node["mountpoint"].startswith("/snap/"):
                mounts.append(node["mountpoint"])
            for ch in node.get("children") or []:
                walk(ch)
        walk(d)
        names = []

        def all_names(node):
            names.append(node["name"])
            for ch in node.get("children") or []:
                all_names(ch)
        all_names(d)
        usage = []
        for mp in mounts:
            try:
                st = os.statvfs(mp)
                usage.append((mp, (st.f_blocks - st.f_bfree) * st.f_frsize, st.f_blocks * st.f_frsize))
            except OSError:
                pass
        rota = d.get("rota") in (True, "1", 1)
        tran = d.get("tran") or ""
        kind = ("usb" if tran == "usb" or d.get("rm") in (True, "1", 1) else "nvme" if d["name"].startswith("nvme")
                else "hdd" if rota else "mmc" if d["name"].startswith("mmcblk") else "ssd")
        _, link = _pci_of(f"/sys/block/{d['name']}/device") if kind == "nvme" else (None, None)
        disk = {"name": d["name"], "model": (d.get("model") or "").strip(), "size": int(d["size"]), "kind": kind,
                "tran": tran, "system": any(root_src.endswith("/" + n) for n in names), "mounts": usage, "link": link,
                "trim": trim, "health": None}
        disk["health"] = _smart(ctx, d["name"]) if ctx.sudo and kind != "usb" else None
        disks.append(disk)
    return disks


def _smart(ctx, name):
    """Drive wear, hours, data written and link speed from smartctl (needs root). A sleeping hard drive isn't woken."""
    out = ctx.run(f"smartctl -n standby -j -a /dev/{shlex.quote(name)}", root=True, timeout=15)
    try:
        j = json.loads(out or "")
    except ValueError:
        return None
    if not j.get("device"):
        return None
    nv = j.get("nvme_smart_health_information_log") or {}
    h = {"passed": (j.get("smart_status") or {}).get("passed"), "hours": (j.get("power_on_time") or {}).get("hours"),
         "rpm": j.get("rotation_rate") if isinstance(j.get("rotation_rate"), int) else None,
         "temp": (j.get("temperature") or {}).get("current"), "used_pct": nv.get("percentage_used"),
         "written": nv.get("data_units_written", 0) * 512000 or None, "spare": nv.get("available_spare"),
         "media_errors": nv.get("media_errors"), "sata_max": None, "sata_now": None}
    speed = j.get("interface_speed") or {}
    h["sata_max"] = (speed.get("max") or {}).get("string")
    h["sata_now"] = (speed.get("current") or {}).get("string")
    for a in (j.get("ata_smart_attributes") or {}).get("table", []):   # SATA SSD wear and data written, when reported
        if a.get("name") in ("Wear_Leveling_Count", "Media_Wearout_Indicator", "Percent_Lifetime_Remain") and h["used_pct"] is None:
            h["used_pct"] = max(0, 100 - a.get("value", 100))
        elif a.get("name") == "Total_LBAs_Written" and not h["written"]:
            h["written"] = (a.get("raw") or {}).get("value", 0) * 512 or None
    return h


def _gpus(ctx):
    nv = {}
    if ctx.has("nvidia-smi"):
        fields = ("pci.bus_id,name,driver_version,memory.total,memory.used,power.draw,power.limit,power.default_limit,"
                  "power.max_limit,temperature.gpu,clocks.max.sm,clocks.max.memory,utilization.gpu,compute_cap,"
                  "vbios_version,fan.speed,pstate")
        for line in ctx.run(f"nvidia-smi --query-gpu={fields} --format=csv,noheader,nounits 2>/dev/null").splitlines():
            p = [x.strip() for x in line.split(",")]
            if len(p) == 17:
                nv[p[0].lower()[-12:]] = dict(zip(fields.split(",")[1:], p[1:]))
        bar1 = parse_nvidia_bar1(ctx.run("nvidia-smi -q -d MEMORY 2>/dev/null")) if nv else {}
        apps = {}
        for line in ctx.run("nvidia-smi --query-compute-apps=gpu_bus_id,pid,process_name,used_memory "
                            "--format=csv,noheader,nounits 2>/dev/null").splitlines():
            p = [x.strip() for x in line.split(",")]
            if len(p) == 4 and p[3].isdigit():
                apps.setdefault(p[0].lower()[-12:], []).append((os.path.basename(p[2]), int(p[3]) << 20))
    gpus = []
    for card in sorted(glob.glob("/sys/class/drm/card[0-9]*")):
        if "-" in os.path.basename(card) or not os.path.exists(f"{card}/device/vendor"):
            continue
        addr, link = _pci_of(f"{card}/device")
        if not addr:
            continue
        vendor = {"0x10de": "nvidia", "0x1002": "amd", "0x8086": "intel"}.get(_sys(f"{card}/device/vendor"), "other")
        info = parse_lspci_vmm(ctx.run(f"lspci -vmm -s {shlex.quote(addr)} 2>/dev/null"))
        drv = os.path.basename(os.path.realpath(f"{card}/device/driver")) if os.path.exists(f"{card}/device/driver") else ""
        name = marketing_name(info.get("Device", "")) or _sys(f"{card}/device/device")
        g = {"card": os.path.basename(card), "addr": addr, "vendor": vendor, "name": name, "codename": info.get("Device", ""),
             "maker": _short_vendor(info.get("SVendor", "")), "driver": drv, "link": link,
             "boot_vga": _sys(f"{card}/device/boot_vga") == "1", "vram": _int(_sys(f"{card}/device/mem_info_vram_total")) or None,
             "vram_used": _int(_sys(f"{card}/device/mem_info_vram_used")) or None, "busy": _int(_sys(f"{card}/device/gpu_busy_percent"), None),
             "nvidia": None, "apps": [], "bar1": None}
        n = nv.get(addr.lower()[-12:])
        if n:
            g.update(name=n["name"].replace("NVIDIA ", ""), vram=_int(n["memory.total"]) << 20, vram_used=_int(n["memory.used"]) << 20,
                     busy=_int(n["utilization.gpu"], None), nvidia=n, apps=sorted(apps.get(addr.lower()[-12:], []), key=lambda a: -a[1]),
                     bar1=bar1.get(addr.lower()[-12:]))
        g["integrated"] = _integrated(g)
        gpus.append(g)
    return gpus


def _short_vendor(v):
    """'Micro-Star International Co., Ltd. [MSI]' -> 'MSI'."""
    m = re.search(r"\[([^\]]+)\]\s*$", v)
    return m.group(1) if m else re.sub(r",? (Co\.|Corp(oration)?|Inc\.?|Ltd\.?|Technology|Computer).*$", "", v).strip()


def _integrated(g):
    """Built into the processor (shares system RAM) rather than a separate graphics card."""
    if g["vendor"] == "intel":
        return not re.search(r"\bArc\b|DG\d|Iris Xe MAX", g["name"])
    if g["vendor"] == "amd":
        return not re.search(r"\bRX\b|\bPro\b|Instinct|FirePro|Vega (?:56|64)|Radeon VII", g["name"])
    return g["vendor"] == "other" and not g["link"]


def _displays(ctx):
    out = []
    for conn in sorted(glob.glob("/sys/class/drm/card*-*")):
        if _sys(f"{conn}/status") != "connected":
            continue
        try:
            with open(f"{conn}/edid", "rb") as fh:
                edid = parse_edid(fh.read())
        except OSError:
            edid = {"name": "", "max_hz": None}
        card, _, port = os.path.basename(conn).partition("-")
        out.append({"card": card, "port": re.sub(r"-A-|-", " ", port).replace("eDP", "built-in screen (eDP)"),
                    "name": edid["name"], "max_hz": edid["max_hz"], "mode": (read(f"{conn}/modes").split() or [""])[0],
                    "internal": port.startswith(("eDP", "LVDS", "DSI"))})
    return out


def _battery(ctx):
    out = []
    for b in sorted(glob.glob("/sys/class/power_supply/*")):
        if _sys(f"{b}/type") != "Battery" or _sys(f"{b}/scope") == "Device":   # not a mouse or headset
            continue
        full = _int(_sys(f"{b}/energy_full")) or _int(_sys(f"{b}/charge_full"))
        design = _int(_sys(f"{b}/energy_full_design")) or _int(_sys(f"{b}/charge_full_design"))
        out.append({"name": os.path.basename(b), "maker": _sys(f"{b}/manufacturer"), "model": _sys(f"{b}/model_name"),
                    "tech": _sys(f"{b}/technology"), "status": _sys(f"{b}/status"), "charge": _int(_sys(f"{b}/capacity"), None),
                    "health": round(full * 100 / design) if full and design else None,
                    "cycles": _int(_sys(f"{b}/cycle_count"), None) or None,
                    "wh": round(_int(_sys(f"{b}/energy_full_design")) / 1e6, 1) or None})
    return out


def _net(ctx):
    out = []
    for n in sorted(glob.glob("/sys/class/net/*")):
        if not os.path.exists(f"{n}/device"):   # virtual: docker bridges, VPNs, loopback
            continue
        addr, _ = _pci_of(f"{n}/device")
        info = parse_lspci_vmm(ctx.run(f"lspci -vmm -s {shlex.quote(addr)} 2>/dev/null")) if addr else {}
        model, vendor = marketing_name(info.get("Device", "")), _short_vendor(info.get("Vendor", "")).split()[0] if info.get("Vendor") else ""
        if vendor and vendor.lower() not in model.lower():
            model = f"{vendor} {model}"
        wifi = os.path.isdir(f"{n}/wireless") or os.path.isdir(f"{n}/phy80211")
        speed = _int(_sys(f"{n}/speed"), -1)
        out.append({"name": os.path.basename(n), "kind": "wifi" if wifi else "ethernet", "model": model,
                    "driver": os.path.basename(os.path.realpath(f"{n}/device/driver")),
                    "up": _sys(f"{n}/operstate") == "up", "speed": speed if speed > 0 else None})
    return out
