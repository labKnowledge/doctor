"""What this computer is, in plain words: hardware.collect()'s facts become sections of rows, each row with a note that
teaches what it means for this computer, and "worth knowing" insights that most people never find out about their own
machine (a monitor in the wrong port, RAM in single channel, a CPU holding back the graphics card...).
Pure functions, no system access: every screen and the assistant show the same thing the same way."""
import os, re, time

PARTS = ["system", "cpu", "memory", "storage", "graphics", "board", "battery", "network"]
ALIASES = {"processor": "cpu", "ram": "memory", "mem": "memory", "disk": "storage", "disks": "storage", "rom": "storage",
           "ssd": "storage", "drives": "storage", "gpu": "graphics", "gpus": "graphics", "display": "graphics",
           "displays": "graphics", "monitor": "graphics", "motherboard": "board", "mobo": "board", "bios": "board",
           "firmware": "board", "os": "system", "net": "network", "wifi": "network", "power": "battery"}
TITLES = {"system": "System", "cpu": "Processor", "memory": "Memory (RAM)", "storage": "Storage", "graphics": "Graphics",
          "board": "Motherboard and firmware", "battery": "Battery", "network": "Network adapters"}
WARN, TIP, INFO = "warn", "tip", "info"
LEVEL_RANK = {WARN: 0, TIP: 1, INFO: 2}
ICON = {WARN: "!", TIP: "→", INFO: "i"}

CHASSIS = {3: "desktop", 4: "desktop", 5: "desktop", 6: "mini tower", 7: "tower", 8: "laptop", 9: "laptop",
           10: "laptop", 11: "handheld", 13: "all-in-one", 14: "laptop", 15: "small desktop", 16: "small desktop",
           17: "server", 23: "server", 24: "desktop", 30: "tablet", 31: "convertible laptop", 32: "detachable laptop",
           35: "mini PC", 36: "stick PC"}
LAPTOPS = {8, 9, 10, 14, 30, 31, 32}


# ---------- numbers people can read ----------

def gb(n):
    """RAM and video memory, the way they're sold (binary): 34359738368 -> '32 GB'."""
    v = n / 2**30
    return f"{v:.0f} GB" if v >= 10 or v == int(v) else f"{v:.1f} GB"


def disk_size(n):
    """Drives, the way they're labelled (decimal): 512110190592 -> '512 GB', 2000398934016 -> '2 TB'."""
    v = n / 1e9
    return f"{v / 1000:.1f} TB".replace(".0 TB", " TB") if v >= 1000 else f"{v:.0f} GB"


def ghz(mhz):
    return f"{mhz / 1000:.1f} GHz"


def ordinal(n):
    return f"{n}{'th' if 10 <= n % 100 <= 20 else {1: 'st', 2: 'nd', 3: 'rd'}.get(n % 10, 'th')}"


def years_since(year, now=None):
    return int(time.strftime("%Y", time.localtime(now))) - year if year else None


# ---------- what generation a part is, and when it came out ----------

INTEL_GEN_YEAR = {1: 2010, 2: 2011, 3: 2012, 4: 2013, 5: 2015, 6: 2015, 7: 2017, 8: 2017, 9: 2018, 10: 2020,
                  11: 2021, 12: 2021, 13: 2022, 14: 2023}
RYZEN_YEAR = {1: 2017, 2: 2018, 3: 2019, 4: 2020, 5: 2020, 6: 2022, 7: 2022, 8: 2024, 9: 2024}
GPU_YEARS = [(r"RTX 50\d\d", 2025), (r"RTX 40\d\d", 2022), (r"RTX 30\d\d", 2020), (r"RTX 20\d\d|TITAN RTX", 2018),
             (r"GTX 16\d\d", 2019), (r"GTX 10\d\d|TITAN X[p ]", 2016), (r"GTX 9\d\d", 2014), (r"GTX 7\d\d", 2013),
             (r"RTX (?:PRO )?\d000 (?:Ada|Blackwell)", 2023), (r"RTX A\d{3,4}", 2021), (r"RX 9\d{3}", 2025),
             (r"RX 7\d{3}", 2022), (r"RX 6\d{3}", 2020), (r"RX 5\d{3}", 2019), (r"Radeon VII|RX Vega", 2017),
             (r"RX 5\d\d\b", 2017), (r"RX 4\d\d\b", 2016), (r"Arc B\d", 2024), (r"Arc A\d", 2022)]


def cpu_name(model):
    """'Intel(R) Core(TM) i7-6700 CPU @ 3.40GHz' -> 'Intel Core i7-6700'."""
    s = re.sub(r"\((?:R|TM|tm|r)\)", "", model or "")
    s = re.sub(r"\s+(?:CPU\s*)?@.*$|\s+\d+-Core Processor$|\s+with Radeon.*$| Processor$|\s+CPU$", "", s)
    return re.sub(r"\s+", " ", s).strip() or "Unknown processor"


def cpu_generation(model):
    """(label, year) for common Intel Core and AMD Ryzen chips; (None, None) when unsure."""
    m = re.search(r"Core\S*\s+i[3579]-(\d{4,5})", model or "")
    if m:
        num = m.group(1)
        gen = int(num[:2]) if len(num) == 5 else int(num[0])
        return f"{ordinal(gen)} gen", INTEL_GEN_YEAR.get(gen)
    m = re.search(r"Core\S*\s+Ultra\s+\d\s+(\d)\d\d", model or "")
    if m:
        return f"Core Ultra series {m.group(1)}", {1: 2023, 2: 2024, 3: 2025}.get(int(m.group(1)))
    if re.search(r"Core\S*\s*2 (?:Duo|Quad)", model or ""):
        return "Core 2", 2007
    if re.search(r"Ryzen\S*\s+AI", model or ""):
        return "Ryzen AI", 2024
    m = re.search(r"Ryzen\S*\s+(?:Threadripper\s+)?(?:PRO\s+)?\d?\s*(\d)\d{3}", model or "")
    if m:
        return f"Ryzen {m.group(1)}000 series", RYZEN_YEAR.get(int(m.group(1)))
    return None, None


def gpu_year(name):
    return next((y for pat, y in GPU_YEARS if re.search(pat, name or "", re.I)), None)


def ai_model_size(vram):
    """The biggest common open model size that fits whole in this much video memory at 4-bit (about 0.6 GB per
    billion parameters, plus ~1.5 GB for the context and the runtime)."""
    usable = vram / 2**30 - 1.5
    return next((b for b in (70, 32, 14, 8, 3) if b * 0.6 <= usable), None)


# ---------- building the sections ----------

def row(label, value, note):
    return {"label": label, "value": value, "note": note}


def insight(level, text, detail):
    return {"level": level, "text": text, "detail": detail}


def build(facts, parts=None, now=None):
    """facts -> [{"key", "title", "rows", "insights"}], only the parts asked for, and only parts this computer has."""
    builders = {"system": _system, "cpu": _cpu, "memory": _memory, "storage": _storage, "graphics": _graphics,
                "board": _board, "battery": _battery, "network": _network}
    out = []
    for key in parts or PARTS:
        try:
            rows, found = builders[key](facts, now)
        except (KeyError, TypeError, ValueError, ZeroDivisionError) as e:
            rows, found = [row("Unreadable", f"{type(e).__name__}", "This part couldn't be read on this computer.")], []
        if rows or found:
            out.append({"key": key, "title": TITLES[key], "rows": rows,
                        "insights": sorted(found, key=lambda i: LEVEL_RANK[i["level"]])})
    return out


def worth_knowing(sections):
    """Every insight across the parts, most important first: [(insight, section)]."""
    return sorted(((i, s) for s in sections for i in s["insights"]), key=lambda x: LEVEL_RANK[x[0]["level"]])


def headline(facts):
    """One line that says what this computer is: model, processor, RAM, graphics, drives."""
    b, cpu, mem = facts.get("board") or {}, facts.get("cpu") or {}, facts.get("memory") or {}
    who = " ".join(x for x in (b.get("vendor"), b.get("product")) if _real(x))
    kind = CHASSIS.get(b.get("chassis"), "")
    parts = [cpu_name(cpu.get("model", ""))]
    types = {d["type"] for d in mem.get("dimms", []) if d.get("type") and d["type"] != "Unknown"}
    if mem.get("total"):
        parts.append(f"{gb(_installed(mem))} RAM" + (f" {types.pop()}" if len(types) == 1 else ""))
    for g in facts.get("gpus") or []:
        if not g["integrated"]:
            parts.append(g["name"] + (f" {gb(g['vram'])}" if g.get("vram") else ""))
    drives = [f"{disk_size(d['size'])} {_kind_short(d)}" for d in facts.get("disks") or [] if d["kind"] != "usb"]
    if drives:
        parts.append(" + ".join(drives))
    return (f"{who} {kind}".strip() or "This computer"), " · ".join(parts)


PLACEHOLDERS = ("to be filled by o.e.m.", "system product name", "system manufacturer", "default string", "o.e.m.",
                "not applicable", "not specified", "none", "type1productconfigid", "base board product name")


def _real(s):
    """Firmware fields that say something: makers often leave 'To be filled by O.E.M.' and the like."""
    return bool(s) and s.strip().lower() not in PLACEHOLDERS


def _installed(mem):
    """Installed RAM: the sticks' sizes when known (the kernel's total leaves out what firmware and graphics reserve)."""
    return sum(d["size"] for d in mem.get("dimms", [])) or mem.get("total", 0)


def _kind_short(d):
    return {"nvme": "NVMe SSD", "ssd": "SSD", "hdd": "hard drive", "usb": "USB drive", "mmc": "eMMC"}[d["kind"]]


# ---------- each part ----------

def _system(f, now):
    o, b = f.get("os") or {}, f.get("board") or {}
    rows, found = [], []
    who = " ".join(x for x in (b.get("vendor"), b.get("product")) if _real(x))
    if who:
        rows.append(row("Computer", who + (f" · {CHASSIS[b['chassis']]}" if b.get("chassis") in CHASSIS else ""),
                        "The model, as its maker calls it. Search for it with 'specs' or 'manual' to find its upgrade "
                        "guide (which RAM and drives fit) and the maker's support page for firmware updates."))
    rows.append(row("Operating system", f"{o.get('name', 'Linux')} · {o.get('arch', '')}",
                    "The software that runs everything else. Ubuntu LTS (Long Term Support) releases get 5 years of "
                    "security updates for free, and up to 10 more with the free personal Ubuntu Pro."))
    rows.append(row("Kernel", o.get("kernel", ""),
                    "The core of Linux: it talks to the hardware (drivers) and shares it out between programs. Newer "
                    "kernels support newer hardware; Ubuntu updates it for you, and it takes effect after a restart."))
    up = o.get("uptime") or 0
    rows.append(row("Running for", _duration(up),
                    "Time since the last start. Updates to the kernel and core libraries only take effect after a "
                    "restart, so restarting every week or two keeps the computer both patched and fresh."))
    if o.get("session"):
        rows.append(row("Desktop", f"{o.get('desktop') or 'desktop'} on {o['session'].capitalize()}",
                        "Wayland is the modern way to draw the screen: smoother and safer (apps can't spy on each other's "
                        "windows). X11 is the older one, still used for some screen-sharing and NVIDIA setups."))
    if o.get("virt") and o["virt"] != "none":
        found.append(insight(INFO, f"This is a virtual machine ({o['virt']})",
                             "The hardware below is what the host lends it, not real parts. Upgrades happen in the "
                             "virtual machine's settings on the host."))
    return rows, found


def _duration(secs):
    d, h = int(secs // 86400), int(secs % 86400 // 3600)
    return f"{d} day{'s' * (d != 1)}, {h} h" if d else f"{h} h {int(secs % 3600 // 60)} min"


def _cpu(f, now):
    c = f.get("cpu") or {}
    if not c.get("model") and not c.get("threads"):
        return [], []
    name = cpu_name(c["model"])
    gen, year = cpu_generation(c["model"])
    age = years_since(year, now)
    rows, found = [], []
    tier = re.search(r"\b(i[3579]|Ultra [579]|Ryzen [3579])\b", name)
    tier_note = {"3": "entry-level", "5": "mainstream", "7": "upper-middle", "9": "top"}.get(tier.group(1)[-1], "") if tier else ""
    rows.append(row("Model", name + (f" · {gen}" if gen else "") + (f" · about {year}" if year else ""),
                    "The processor (CPU) is the computer's brain: it runs every program."
                    + (f" '{tier.group(1)}' is the maker's {tier_note} tier" if tier_note else "")
                    + (f"; this {gen} came out around {year}, about {age} years ago." if year and age is not None else ".")))
    hybrid = c.get("p_cores") and c.get("e_cores")
    cores = (f"{c['p_cores']} performance + {c['e_cores']} efficiency threads" if hybrid
             else f"{c['cores']} cores · {c['threads']} threads")
    rows.append(row("Cores", cores + (f" · {c['sockets']} processors" if c.get("sockets", 1) > 1 else ""),
                    ("Performance cores run what you're doing; efficiency cores take background work to save power. "
                     if hybrid else "A core is one worker that runs a program. ")
                    + ("Threads let each core juggle two jobs at once (Hyper-Threading / SMT), worth about 20-30% more. "
                       if c["threads"] > c["cores"] else "")
                    + f"{c['cores']} cores handle browsing, office work and most games; video export, compiling code and "
                      "3D rendering get faster with more."))
    speed = []
    if c.get("base_mhz"):
        speed.append(f"{ghz(c['base_mhz'])} base")
    if c.get("max_mhz"):
        speed.append(f"up to {ghz(c['max_mhz'])}")
    if c.get("cur_mhz"):
        lo, hi = c["cur_mhz"]
        speed.append(f"now {ghz(lo)}" + (f"-{ghz(hi)}" if hi - lo > 50 else ""))
    if speed:
        rows.append(row("Speed", " · ".join(speed),
                        "GHz is how many billion steps a core takes each second. Base is what it always sustains; it "
                        "boosts above that when it's busy and cool enough. Running slower when idle is normal: it saves "
                        "power and keeps it quiet."))
    cache = " · ".join(f"{_cache(v)} {k}" for k, v in (("L3", c.get("l3")), ("L2", c.get("l2"))) if v)
    if cache:
        rows.append(row("Cache", cache,
                        "Cache is a small, very fast memory inside the processor that keeps the data it's about to need, "
                        "so it waits less on RAM. A bigger L3 helps games and large programs. It can't be upgraded."))
    flags = set(c.get("flags") or [])
    feats = [n for k, n in (("avx512f", "AVX-512"), ("avx2", "AVX2"), ("aes", "AES"), ("sha_ni", "SHA")) if k in flags]
    if c.get("virt"):
        feats.append(f"{c['virt']} virtualization")
    if feats:
        rows.append(row("Features", " · ".join(feats),
                        "Built-in shortcuts for specific jobs. AVX2/AVX-512 speed up math-heavy work (video, photo "
                        "filters, AI) and many new games and AI tools require AVX2. AES makes encryption (disk, HTTPS, VPN) "
                        "almost free. Virtualization runs virtual machines and Android emulators at near full speed."))
    if c.get("governor"):
        pstate = c.get("driver") in ("intel_pstate", "amd-pstate-epp", "amd-pstate")
        rows.append(row("Power mode", c["governor"] + (f" · {c['epp'].replace('_', ' ')}" if c.get("epp") else ""),
                        ("With this processor's driver, 'powersave' still reaches full speed whenever there's work; it "
                         "isn't a slow mode. The second part is how eagerly it speeds up. "
                         if pstate and c["governor"] == "powersave" else
                         "How the processor picks its speed: 'performance' stays fast, 'powersave'/'schedutil' follow the load. ")
                        + "Ubuntu's power mode (Settings > Power) changes this."))
    if c.get("microcode"):
        rows.append(row("Microcode", c["microcode"],
                        "The processor's own small firmware, loaded at every start. Ubuntu ships updates for it "
                        "(intel-microcode / amd64-microcode) that fix CPU bugs and security flaws like Spectre."))

    if year and age is not None and age >= 7:
        found.append(insight(INFO, f"The processor is about {age} years old ({gen}, {year})",
                             "Still fine for the web, office work and video. If the computer feels slow while the processor "
                             "is busy (Top apps shows it), it's the part to upgrade, and on a platform this old that usually "
                             "means a new motherboard and RAM along with it."))
    if c.get("arch") == "x86_64" and "avx2" not in flags and "hypervisor" not in flags:
        found.append(insight(WARN, "No AVX2: some modern programs won't run",
                             "Many recent games and AI tools (llama.cpp builds, TensorFlow) need AVX2, which processors "
                             "have had since about 2013 (Intel) and 2015 (AMD). Use builds made for older CPUs, or plan an upgrade."))
    virt_off = c.get("arch") == "x86_64" and not ({"vmx", "svm"} & flags) and "hypervisor" not in flags
    if virt_off:
        found.append(insight(TIP, "Virtualization is off",
                             "Virtual machines, Android emulators and some development tools need it. Nearly every processor "
                             "since 2010 has it: turn on 'Intel VT-x' or 'SVM Mode' in the BIOS setup (the key at power-on, "
                             "often F2 or Del)."))
    if c.get("smt") in ("off", "forceoff") and "ht" in flags:
        found.append(insight(INFO, "Hyper-Threading (SMT) is turned off",
                             f"Only {c['threads']} of {c['cores'] * 2} possible threads run. That's sometimes done for "
                             "security on shared servers; on a personal computer, turning it back on (BIOS setup) gives "
                             "about 20-30% more for multitasking and heavy work."))
    return rows, found


def _cache(s):
    """'8 MiB (1 instance)' -> '8 MB'."""
    m = re.match(r"([\d.]+)\s*([KMG])i?B", s or "")
    return f"{m.group(1)} {m.group(2)}B" if m else s


def _memory(f, now):
    m = f.get("memory") or {}
    if not m.get("total"):
        return [], []
    dimms, rows, found = m.get("dimms") or [], [], []
    installed = _installed(m)
    types = sorted({d["type"] for d in dimms if d.get("type") and d["type"] != "Unknown"})
    speeds = sorted({d["configured"] or d["speed"] for d in dimms if d["configured"] or d["speed"]})
    rows.append(row("Installed", gb(installed) + (f" {'/'.join(types)}" if types else "")
                    + (f" at {speeds[0]} MT/s" if len(speeds) == 1 else ""),
                    "RAM is the computer's short-term workspace: every open app and tab lives here. When it fills up, "
                    "Linux moves the overflow to swap on the drive, which is much slower; that's when a computer starts "
                    "to crawl. DDR4 and DDR5 are generations: sticks only fit the kind the motherboard is made for."))
    if dimms:
        groups = {}
        for d in dimms:
            groups.setdefault((d["size"], d["maker"], d["part"]), []).append(d)
        sticks = " + ".join(f"{len(g)} × {gb(size)}" + (f" {maker}" if maker and maker != "Unknown" else "")
                            + (f" ({part})" if part and part.lower() not in ("unknown", "") else "")
                            for (size, maker, part), g in groups.items())
        rows.append(row("Sticks", sticks,
                        "Each stick sits in a slot on the motherboard. The part number tells you exactly which stick it "
                        "is: search it to buy a matching one. Matching sticks (same size and speed) work best together."))
    if m.get("slots"):
        free = m["slots"] - len(dimms)
        cap = f" · board takes up to {gb(m['max_capacity'])}" if m.get("max_capacity") and m["max_capacity"] >= installed else ""
        rows.append(row("Slots", f"{len(dimms)} of {m['slots']} used" + (f", {free} free" if free > 0 else "") + cap,
                        "How much room there is to grow: free slots, and the most the motherboard accepts (as its "
                        "firmware reports it; the processor's own limit can be lower, and some boards take more than "
                        "they say with newer, larger sticks)."))
    if dimms:
        n, sizes = len(dimms), {d["size"] for d in dimms}
        mode = ("single channel" if n == 1 else "dual channel" if n % 2 == 0 and len(sizes) == 1
                else "dual channel, partly (sticks differ in size)" if n >= 2 else "")
        rated = max((d["speed"] for d in dimms), default=0)
        conf = min((d["configured"] for d in dimms if d["configured"]), default=0)
        speed = f"{conf or rated} MT/s" + (f" (rated {rated})" if conf and rated and conf < rated else "")
        rows.append(row("Speed", f"{speed} · {mode}" if mode else speed,
                        "MT/s is millions of transfers per second: how fast the processor gets data from RAM. With sticks "
                        "in matching pairs the processor uses two lanes (channels) at once, doubling the speed for free. "
                        "It matters most for built-in graphics and games."))
        if any(d["ecc"] for d in dimms):
            rows.append(row("Error correction", "ECC",
                            "ECC memory detects and fixes flipped bits on its own, so a cosmic ray or a weak cell can't "
                            "silently corrupt data. Common in servers and workstations."))
    used = m["total"] - m.get("available", 0)
    swap = f" · swap: {gb(m['swap_used'])} of {gb(m['swap_total'])}" if m.get("swap_total") else " · no swap"
    rows.append(row("In use now", f"{gb(used)} used, {gb(m.get('available', 0))} free{swap}",
                    "'Free' counts what Linux can hand out right away; it borrows idle RAM to cache files and gives it "
                    "back when an app needs it, so low free memory alone is fine. Swap in use means RAM ran short at "
                    "some point and the overflow went to the drive."
                    + (" Part of it is zram: compressed swap kept in RAM, much faster than the drive." if m.get("zram") else "")))

    if len(dimms) == 1 and m.get("slots", 1) > 1:
        found.append(insight(TIP, "One memory stick: it runs in single channel",
                             f"The processor can read from two sticks at once. Adding a second {gb(dimms[0]['size'])} "
                             f"{dimms[0]['type']} stick like it ({dimms[0]['part'] or 'same size and speed'}) doubles memory "
                             "bandwidth: a big boost for built-in graphics, noticeable in games and heavy apps."))
    slow = [d for d in dimms if d["configured"] and d["speed"] and d["configured"] < d["speed"]]
    if slow:
        found.append(insight(TIP, f"RAM runs at {slow[0]['configured']} MT/s, rated for {slow[0]['speed']}",
                             "The motherboard picked a safe, slower speed. If the processor and board support the "
                             "faster one, turning on XMP (Intel) or EXPO/DOCP (AMD) in the BIOS setup gives it for free."))
    short = m.get("swap_used", 0) > max(installed * 0.25, 2 * 2**30) or m.get("available", 0) < m["total"] * 0.08
    if short:
        free = m.get("slots", 0) - len(dimms)
        cap = m.get("max_capacity") or 0
        if free > 0:
            grow = f"There {'is' if free == 1 else 'are'} {free} free slot{'s' * (free > 1)}" + (f" (up to {gb(cap)} in all)" if cap else "") + "."
        elif cap > installed and dimms:
            grow = (f"All slots are full: to grow, replace the {gb(dimms[0]['size'])} sticks with bigger ones "
                    f"(the board takes up to {gb(cap)}).")
        elif cap and cap <= installed:
            grow = "It's already at the board's maximum: closing heavy apps is the way."
        else:
            grow = "Check the computer's manual for how much it takes."
        spilled = m.get("swap_used", 0) > 2**30
        found.append(insight(WARN, f"Memory runs short: {gb(m['swap_used'])} has spilled to the drive" if spilled
                             else "Memory is almost full right now",
                             "Apps wait on the much slower drive whenever they touch that part. More RAM is the fix that "
                             "works. " + grow))
    elif installed < 7.5 * 2**30:
        found.append(insight(TIP, f"{gb(installed)} of RAM is tight today",
                             "A modern browser with a dozen tabs uses 3-4 GB by itself; 8 GB is comfortable, 16 GB roomy."))
    return rows, found


def _storage(f, now):
    disks = f.get("disks") or []
    rows, found = [], []
    disks = sorted(disks, key=lambda d: (not d["system"], d["kind"] == "usb", d["name"]))
    for d in disks:
        label = "System drive" if d["system"] else f"{'USB' if d['kind'] == 'usb' else 'Data'} drive {d['name']}"
        kind = {"nvme": "NVMe SSD", "ssd": "SATA SSD" if d["tran"] == "sata" else "SSD", "hdd": "hard drive",
                "usb": "USB drive", "mmc": "eMMC / SD card"}[d["kind"]]
        link = d.get("link")
        lanes = (f" · PCIe {link['gen']}.0 x{link['width']} (up to ~{_pcie_gbs(link['gen'], link['width'])} GB/s)"
                 if link and link.get("gen") and link.get("width") else "")
        h = d.get("health") or {}
        rpm = f", {h['rpm']} rpm" if h.get("rpm") else ""
        rows.append(row(label, f"{disk_size(d['size'])} {kind}{rpm} · {d['model'] or 'unnamed'}{lanes}", _drive_note(d)))
        for mp, used, total in d["mounts"]:
            if total > 2 * 2**30:
                rows.append(row(f"  {_mount_label(mp)}", f"{disk_size(used)} of {disk_size(total)} used ({used * 100 // total}%)",
                                "A part of this drive (a partition) and the folder where it appears. Drives fill up "
                                "silently: doctor clean clears caches, doctor deep finds big things safe to delete."))
        if h:
            bits = []
            if h.get("used_pct") is not None:
                bits.append(f"{h['used_pct']}% worn")
            if h.get("hours"):
                bits.append(f"on for {h['hours']:,} h (~{h['hours'] / 8766:.1f} years)")
            if h.get("written"):
                bits.append(f"{disk_size(h['written'])} written")
            if h.get("temp"):
                bits.append(f"{h['temp']}°C")
            if bits:
                rows.append(row("  health", " · ".join(bits),
                                "From the drive's own self-monitoring (SMART). An SSD wears a little with every write: "
                                "'worn' is its own estimate of how much of its rated life is used, and most outlast "
                                "the computer. Hours count the time it has been powered."))
            if h.get("used_pct") is not None and h["used_pct"] >= 80:
                found.append(insight(WARN, f"{d['model']} has used {h['used_pct']}% of its rated life",
                                     "Back up what's on it now, and plan to replace it. Worn SSDs often turn read-only first."))
            elif h.get("used_pct") is not None and h["used_pct"] >= 50:
                found.append(insight(INFO, f"{d['model']} is {h['used_pct']}% worn",
                                     "Fine for now; keep backups current and check again in a few months."))
            if d["kind"] == "hdd" and (h.get("hours") or 0) > 40000:
                found.append(insight(TIP, f"The hard drive {d['name']} has run for {h['hours'] / 8766:.0f} years",
                                     "Hard drives fail more often after about 5 years of use. Keep a backup of anything "
                                     "on it you'd miss."))
            if h.get("sata_max") and h.get("sata_now") and h["sata_now"] != h["sata_max"] and d["kind"] == "ssd":
                found.append(insight(WARN, f"{d['model']} runs at {h['sata_now']} instead of {h['sata_max']}",
                                     "It's on a slower SATA port or cable. Move it to a SATA 3 (6 Gb/s) port, usually "
                                     "the first ones on the board, or try another cable."))
        if link and link.get("gen") and link.get("max_gen") and link["gen"] < link["max_gen"] and (link.get("slot_gen") or 9) < link["max_gen"]:
            found.append(insight(INFO, f"{d['model']} could go faster in another slot",
                                 f"It supports PCIe {link['max_gen']}.0 but this slot gives {link['gen']}.0. Everyday use "
                                 "won't feel it; big file copies would."))
    if not disks:
        return rows, found
    if not any(d["health"] for d in disks if d["kind"] != "usb") and not f.get("sudo"):
        rows.append(row("  health", "wear and hours need sudo: doctor sysinfo storage --sudo",
                        "How worn each drive is comes from the drive itself (SMART), which only root can ask."))
    system = next((d for d in disks if d["system"]), None)
    virtual = (f.get("os") or {}).get("virt") not in (None, "", "none")   # a VM's disks can claim anything
    if system and system["kind"] == "hdd" and not virtual:
        found.append(insight(WARN, "Ubuntu runs from a hard drive",
                             "It's the slowest part of this computer: starting up and opening apps wait on it. Moving "
                             "the system to an SSD, even a cheap one, is the biggest speed-up money can buy here."))
    if any(d["kind"] in ("ssd", "nvme") for d in disks) and system and system["trim"] not in ("enabled", "static", ""):
        found.append(insight(TIP, "TRIM is off for the SSD",
                             "TRIM tells the SSD which space is free, keeping it fast and lowering wear. "
                             "Turn on the weekly job: sudo systemctl enable --now fstrim.timer"))
    return rows, found


def _mount_label(mp):
    """'/media/you/storage' -> 'storage': the name the file manager shows, short enough for a column."""
    return os.path.basename(mp) if re.match(r"^/(media/[^/]+|mnt|run/media/[^/]+)/[^/]+$", mp) else mp


def _drive_note(d):
    base = {"nvme": "An NVMe SSD plugs straight into PCIe lanes: the fastest kind of drive, with no moving parts. Opening "
                    "apps and starting up feel instant compared with a hard drive. ",
            "ssd": "An SSD (solid-state drive): no moving parts, silent, and many times faster than a hard drive at opening "
                   "apps. The SATA connection caps it at about 550 MB/s, a fifth of a modern NVMe drive. ",
            "hdd": "A hard drive: spinning platters and a moving head. Cheap per terabyte and fine for storage and backups, "
                   "but around 100 times slower than an SSD at the small reads that starting apps needs. ",
            "usb": "A removable USB drive. ",
            "mmc": "Built-in flash storage (eMMC) or an SD card: slower than an SSD, common in small laptops. "}[d["kind"]]
    link = d.get("link")
    if link and link.get("gen"):
        base += (f"PCIe {link['gen']}.0 x{link['width']} means {link['width']} lane{'s' * (link['width'] > 1)} of "
                 f"generation {link['gen']}; each generation doubles the speed per lane. ")
    return base + ("Ubuntu itself lives on this one." if d["system"] else "")


def _pcie_gbs(gen, width):
    per_lane = {1: 0.25, 2: 0.5, 3: 0.985, 4: 1.97, 5: 3.94, 6: 7.56}.get(gen, 0)
    v = per_lane * width
    return f"{v:.0f}" if v >= 10 else f"{v:.1f}".rstrip("0").rstrip(".")


def _graphics(f, now):
    gpus, displays = f.get("gpus") or [], f.get("displays") or []
    rows, found = [], []
    cpu_year = cpu_generation((f.get("cpu") or {}).get("model", ""))[1]
    board = f.get("board") or {}
    many = len(gpus) > 1
    for g in gpus:
        label = "Built-in graphics" if g["integrated"] else "Graphics card"
        year = gpu_year(g["name"])
        value = g["name"] + (f" · {g['maker']}" if g.get("maker") and g["maker"] not in g["name"] else "")
        value += (f" · {gb(g['vram'])}" if g.get("vram") and not g["integrated"] else "") + (f" · about {year}" if year else "")
        rows.append(row(label, value,
                        "Graphics built into the processor: it shares the system RAM, and is fine for the desktop, video "
                        "and light games." if g["integrated"] else
                        "A separate graphics card (GPU) with its own fast memory. It draws the screen and runs games, 3D and "
                        "video encoding, and does AI and other parallel math many times faster than the processor."))
        n = g.get("nvidia") or {}
        if g.get("vram") and not g["integrated"]:
            used = f" · {gb(g['vram_used'])} in use" if g.get("vram_used") is not None else ""
            apps = ", ".join(f"{name} {gb(b)}" for name, b in g["apps"][:3])
            rows.append(row("  video memory", f"{gb(g['vram'])}{used}" + (f" ({apps})" if apps else ""),
                            "VRAM is the card's own memory for textures, frames and AI models. What doesn't fit spills "
                            "into system RAM over the slot, and that is many times slower: the main limit for games at "
                            "high settings and for which AI models run fast. " + _vram_class(g["vram"])))
        drv = g["driver"] or "none"
        drv_value = {"nvidia": f"NVIDIA's own driver {n.get('driver_version', '')}".strip(), "nouveau": "nouveau (open source)",
                     "amdgpu": "amdgpu (open source, AMD's own)", "radeon": "radeon (old open-source driver)",
                     "i915": "i915 (Intel)", "xe": "xe (Intel)", "none": "no driver loaded"}.get(drv, drv)
        rows.append(row("  driver", drv_value,
                        "The driver is the software that lets Ubuntu use the card. "
                        + {"nvidia": "NVIDIA's own driver gives full speed and CUDA, which AI and video tools use.",
                           "nouveau": "nouveau works for the desktop but is far slower than NVIDIA's own driver and has no CUDA.",
                           "amdgpu": "For AMD cards the open-source driver built into Linux is the best one; nothing to install.",
                           "none": "Without one, the card does nothing."}.get(drv, "Intel's drivers come built into Linux.")))
        link = g.get("link")
        if link and link.get("max_gen") and not g["integrated"]:
            best_gen = min(link["max_gen"], link.get("slot_gen") or link["max_gen"])
            value = f"PCIe {best_gen}.0 x{link['width']}"
            if link["max_gen"] > best_gen:
                value += f" (card can do {link['max_gen']}.0)"
            if link.get("gen") and link["gen"] < best_gen:
                value += f" · resting at {link['gen']}.0 now"
            rows.append(row("  connection", value,
                            "PCIe is the slot the card plugs into. Each generation doubles the speed per lane, and x16 "
                            "is the full-width slot. Cards slow the link down when idle to save power, so a lower 'now' "
                            "is normal."))
            if link.get("width") and link.get("max_width") and link["width"] < link["max_width"] and board.get("chassis") not in LAPTOPS:
                if link.get("slot_width") and link["slot_width"] < link["max_width"]:
                    found.append(insight(TIP, f"The {g['name']} sits in an x{link['slot_width']} slot",
                                         f"It's built for x{link['max_width']}. If the motherboard has a longer (x16) slot, "
                                         "usually the one nearest the processor, moving the card there gives it full speed."))
                else:
                    found.append(insight(WARN, f"The {g['name']} runs on x{link['width']} lanes instead of x{link['max_width']}",
                                         "The slot is full width but only part of it connects: the card may not be fully "
                                         "seated, the slot is dusty, or a riser cable is limiting it. Reseat it with the "
                                         "computer unplugged."))
            if link.get("slot_gen") and link["slot_gen"] < link["max_gen"]:
                found.append(insight(INFO, f"The {g['name']} runs at PCIe {link['slot_gen']}.0, below its {link['max_gen']}.0",
                                     "The motherboard's slot is the older generation. In games this costs only a few percent; "
                                     "it matters more when a game or AI model doesn't fit in video memory."))
        if n:
            power = f"{float(n['power.draw']):.0f} W now" if _num(n.get("power.draw")) else ""
            limit = f"limit {float(n['power.limit']):.0f} W" if _num(n.get("power.limit")) else ""
            temp = f"{n['temperature.gpu']}°C" if _num(n.get("temperature.gpu")) else ""
            fan = f"fan {n['fan.speed']}%" if _num(n.get("fan.speed")) else ""
            if power or temp:
                rows.append(row("  power and heat", " · ".join(x for x in (power, limit, temp, fan) if x),
                                "How much electricity the card draws now, and the most it's allowed to. Big cards need a "
                                "power supply with headroom above that limit. Many cards stop their fans below about "
                                "55°C to stay silent: 0% at idle is normal."))
            if _num(n.get("power.limit")) and _num(n.get("power.default_limit")) and float(n["power.limit"]) < float(n["power.default_limit"]) - 5:
                found.append(insight(INFO, f"The {g['name']} is power-limited to {float(n['power.limit']):.0f} W "
                                           f"(normally {float(n['power.default_limit']):.0f} W)",
                                     "Someone (or a tool) lowered it: the card runs cooler and quieter but slower under load. "
                                     f"Back to normal: sudo nvidia-smi -pl {float(n['power.default_limit']):.0f}"))
            if n.get("compute_cap"):
                rows.append(row("  CUDA", f"compute capability {n['compute_cap']}",
                                "Which generation of NVIDIA's computing features the card has. AI tools check it: 7.5 and "
                                "newer runs current PyTorch, llama.cpp and Ollama builds with every speed-up."))
        size = ai_model_size(g["vram"]) if g.get("vram") and not g["integrated"] and (n or g["vendor"] == "amd") else None
        if size:
            rows.append(row("  local AI", f"models up to about {size}B parameters fit entirely in its memory",
                            "A rough guide for open AI models (Llama, Qwen, Mistral...) in the common 4-bit size, as Ollama "
                            "and LM Studio download them. When the whole model fits in video memory it runs fast; bigger "
                            "ones still run, partly on the processor, many times slower."))
        if g.get("bar1") and g.get("vram") and g["vram"] > 2 * 2**30:
            on = g["bar1"] * 2**20 >= g["vram"] * 0.9
            supported = (cpu_year or 0) >= 2020 and board.get("uefi")
            rows.append(row("  Resizable BAR", "on" if on else "off" + ("" if supported else " (this platform is too old for it)"),
                            "Lets the processor reach all of the card's memory at once instead of through a 256 MB window. "
                            "Some games gain a few percent. It needs a recent processor and motherboard, UEFI boot, and a "
                            "BIOS setting."))
            if not on and supported:
                found.append(insight(TIP, "Resizable BAR is off",
                                     "In the BIOS setup, turn on 'Above 4G Decoding' and 'Re-Size BAR Support' (CSM must be "
                                     "off). Some games run up to ~10% faster; nothing gets slower."))
        if g["vendor"] == "nvidia" and drv in ("nouveau", "none"):
            found.append(insight(WARN, f"The {g['name']} isn't using NVIDIA's driver",
                                 "It's running far below its speed, with no CUDA for AI or video tools. Install the right "
                                 "driver with: sudo ubuntu-drivers install, then restart."))
        year_gap = (year - cpu_year) if year and cpu_year else 0
        if not g["integrated"] and year_gap >= 5:
            found.append(insight(TIP, f"The processor is about {year_gap} years older than the {g['name']}",
                                 "In games the processor often can't prepare frames fast enough to keep this card busy, so "
                                 "you get less than the card can do, most at 1080p and least at 4K. Raising resolution and "
                                 "detail costs little here. AI work that fits in video memory barely notices."))
        if g.get("vram") and g.get("vram_used") and g["vram_used"] > g["vram"] * 0.9 and not g["integrated"]:
            who = g["apps"][0][0] if g["apps"] else "programs"
            found.append(insight(INFO, f"Video memory is {g['vram_used'] * 100 // g['vram']}% full",
                                 f"Mostly {who}. A game or model started now won't fit and will run slowly until that closes."))
    for d in displays:
        on = next((g for g in gpus if g["card"] == d["card"]), None)
        hz = f" · up to {d['max_hz']} Hz" if d.get("max_hz") else ""
        rows.append(row("Screen" if d["internal"] else "Monitor",
                        f"{d['name'] or 'unnamed'} · {d['mode'] or '?'}{hz}" + (f" · on {on['name']} ({d['port']})" if on and many else f" · {d['port']}"),
                        "The resolution is how many dots (pixels) make up the picture; refresh rate (Hz) is how many times "
                        "a second it's redrawn, and higher feels smoother. These are what the screen itself says it supports."))
        if d.get("max_hz") and d["max_hz"] >= 100:
            found.append(insight(TIP, f"{d['name'] or 'Your monitor'} can do up to {d['max_hz']} Hz",
                                 "Check that Settings > Displays > Refresh Rate uses it; many people leave it at 60 Hz without "
                                 "knowing. Higher needs a DisplayPort or recent HDMI cable."))
    discrete = [g for g in gpus if not g["integrated"] and g["driver"]]
    external = [d for d in displays if not d["internal"]]
    if discrete and external and board.get("chassis") not in LAPTOPS:
        on_igpu = [d for d in external if any(g["card"] == d["card"] and g["integrated"] for g in gpus)]
        if on_igpu and len(on_igpu) == len(external):
            found.append(insight(WARN, "The monitor is plugged into the motherboard, not the graphics card",
                                 f"Games and videos then run on the weaker built-in graphics instead of the {discrete[0]['name']}. "
                                 "Move the cable to the ports on the graphics card itself (the lower, horizontal ones at the back)."))
    return rows, found


def _vram_class(vram):
    v = vram / 2**30
    return ("This much suits light games at low settings." if v < 3.5 else
            "This much suits 1080p gaming at medium settings." if v < 7.5 else
            "This much suits 1080p and 1440p gaming at high settings." if v < 11.5 else
            "This much suits 1440p and 4K gaming, and mid-size AI models." if v < 15.5 else
            "This much handles 4K gaming at top settings and big AI models.")


def _num(s):
    try:
        float(s)
        return True
    except (TypeError, ValueError):
        return False


def _board(f, now):
    b = f.get("board") or {}
    if not b or b.get("error"):
        return [], []
    rows, found = [], []
    if b.get("board"):
        rows.append(row("Motherboard", " ".join(x for x in (b.get("board_vendor"), b.get("board")) if _real(x)) or "unnamed",
                        "The main board everything plugs into. It decides which processors, how much and which kind of "
                        "RAM, and which drives and cards the computer can take, so it's the first thing to look up "
                        "before an upgrade."))
    year = None
    m = re.search(r"(\d{4})$", b.get("bios_date", ""))
    if m:
        year = int(m.group(1))
    if b.get("bios_version"):
        when = time.strftime("%b %Y", time.strptime(b["bios_date"], "%m/%d/%Y")) if re.fullmatch(r"\d\d/\d\d/\d{4}", b.get("bios_date", "")) else b.get("bios_date", "")
        rows.append(row("Firmware (BIOS)", f"{b['bios_version']} · {when}" + (f" · {b['bios_vendor']}" if b.get("bios_vendor") else ""),
                        "The firmware starts the computer before Ubuntu: it checks the hardware and hands over. Makers "
                        "release updates for security fixes and support for newer parts, usually for a few years."))
    boot = ("UEFI" if b.get("uefi") else "legacy BIOS") + (
        "" if not b.get("uefi") else " · Secure Boot " + ("on" if b.get("secure_boot") else "off" if b.get("secure_boot") is False else "unknown"))
    rows.append(row("Boot mode", boot,
                    "UEFI is the modern way to start a computer (legacy BIOS is the old one). Secure Boot lets only signed "
                    "software start the computer, which blocks malware that hides below the operating system."))
    rows.append(row("Security chip", f"TPM {b['tpm']}" + (".0" if b["tpm"].isdigit() else "") if b.get("tpm") else "none found",
                    "A TPM is a small chip that keeps encryption keys safe. Disk encryption that unlocks itself at "
                    "startup and Windows 11 use it."))
    age = years_since(year, now)
    if age is not None and age >= 6:
        found.append(insight(INFO, f"The firmware dates from {year}",
                             f"Look up '{b.get('vendor', '')} {b.get('product', '')} BIOS' on the maker's support page: newer firmware fixes "
                             "security flaws (including processor ones). If there's nothing newer, nothing to do. Update "
                             "carefully: plugged in, and never interrupted."))
    if not b.get("uefi"):
        found.append(insight(INFO, "The computer starts in legacy BIOS mode",
                             "It works, but Secure Boot and some newer features need UEFI. Switching an installed system "
                             "over isn't simple; it's worth doing at the next reinstall."))
    elif b.get("secure_boot") is False:
        found.append(insight(INFO, "Secure Boot is off",
                             "Fine if you use unsigned drivers or kernels. Otherwise turning it on (BIOS setup) blocks "
                             "malware that loads before Ubuntu."))
    return rows, found


def _battery(f, now):
    rows, found = [], []
    for bat in f.get("battery") or []:
        bits = [f"{bat['charge']}% charged" if bat.get("charge") is not None else "", bat.get("status", "").lower()]
        rows.append(row("Battery", " · ".join(x for x in bits if x) + (f" · {bat['wh']} Wh new" if bat.get("wh") else ""),
                        "Wh (watt-hours) is how much energy it held when new. Lithium batteries last longest kept "
                        "between about 20% and 80%; some laptops have a setting to stop charging at 80%."))
        if bat.get("health"):
            rows.append(row("  health", f"holds {bat['health']}% of its original charge"
                            + (f" · {bat['cycles']} charge cycles" if bat.get("cycles") else ""),
                            "Every battery loses capacity as it ages and cycles (one cycle = 100% used, in any number of "
                            "charges). Most are rated for 300-1000 cycles to 80%."))
            if bat["health"] < 60:
                found.append(insight(WARN, f"The battery holds only {bat['health']}% of what it did",
                                     "Expect much shorter time unplugged, and sudden shutdowns at low charge. A replacement "
                                     "battery fixes it; search the laptop model plus 'battery'."))
            elif bat["health"] < 80:
                found.append(insight(INFO, f"The battery is worn to {bat['health']}%",
                                     "Normal after a few years. Keeping it between 20% and 80% slows further wear."))
    return rows, found


def _network(f, now):
    rows, found = [], []
    for n in f.get("net") or []:
        kind = "Wi-Fi" if n["kind"] == "wifi" else "Ethernet"
        state = (f"{n['speed']} Mb/s" if n.get("speed") else "connected") if n["up"] else "not connected"
        rows.append(row(f"{kind} ({n['name']})", f"{n['model'] or n['driver']} · {state}",
                        "Wi-Fi speed depends on the router, distance and walls; a cable is faster and steadier. "
                        if n["kind"] == "wifi" else
                        "A wired connection: Mb/s is the speed agreed with the router (1000 = gigabit). "
                        "It's usually faster and steadier than Wi-Fi."))
        if n["kind"] == "ethernet" and n["up"] and n.get("speed") in (10, 100):
            found.append(insight(TIP, f"The network cable connects at only {n['speed']} Mb/s",
                                 "Almost every card and router today does 1000. A damaged or old cable (or one with only "
                                 "4 wires) causes this: try another cable, or another port on the router."))
    return rows, found


# ---------- text for the assistant and for --json ----------

def as_text(facts, sections=None):
    """Compact plain text: what the assistant reads before answering a question about this computer."""
    who, parts = headline(facts)
    lines = [f"{who}: {parts}"]
    for s in sections or build(facts):
        lines.append(f"{s['title']}:")
        lines += [f"  {r['label'].strip()}: {r['value']}" for r in s["rows"]]
        lines += [f"  ({i['level']}) {i['text']}" for i in s["insights"]]
    return "\n".join(lines)


def resolve(words):
    """Part names as typed ('gpu', 'ram', 'disk') -> PARTS keys; unknown words come back as the second value."""
    keys, bad = [], []
    for w in words:
        k = ALIASES.get(w.lower(), w.lower())
        (keys if k in PARTS else bad).append(k if k in PARTS else w)
    return [k for k in PARTS if k in keys], bad
