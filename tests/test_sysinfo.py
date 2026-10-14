"""Run: python3 -m unittest discover -s tests   doctor sysinfo: parsers on captured output, and what's worth knowing
about made-up computers (no system access, except the last test, which reads this computer read-only)."""
import copy, io, json, os, sys, tempfile, unittest
from contextlib import redirect_stdout
from pathlib import Path

os.environ.setdefault("DOCTOR_DATA", tempfile.mkdtemp(prefix="doctor-test-"))
os.environ["DOCTOR_NO_AGENT"] = "1"
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from doctor import hardware, sysinfo  # noqa: E402
from doctor.cli import main  # noqa: E402

GiB = 2**30
UDEV = """P: /devices/virtual/dmi/id
E: MEMORY_ARRAY_MAX_CAPACITY=68719476736
E: MEMORY_DEVICE_0_SIZE=8589934592
E: MEMORY_DEVICE_0_TYPE=DDR4
E: MEMORY_DEVICE_0_SPEED_MTS=3200
E: MEMORY_DEVICE_0_CONFIGURED_SPEED_MTS=2400
E: MEMORY_DEVICE_0_MANUFACTURER=Kingston
E: MEMORY_DEVICE_0_PART_NUMBER=KF432C16BB/8
E: MEMORY_DEVICE_0_LOCATOR=DIMM_A1
E: MEMORY_DEVICE_0_TOTAL_WIDTH=64
E: MEMORY_DEVICE_0_DATA_WIDTH=64
E: MEMORY_DEVICE_1_PRESENT=0
E: MEMORY_DEVICE_1_LOCATOR=DIMM_B1
E: MEMORY_ARRAY_NUM_DEVICES=2
"""


def edid(name, max_hz):
    b = bytearray(128)
    b[:8] = b"\x00\xff\xff\xff\xff\xff\xff\x00"
    b[54:72] = bytes([0, 0, 0, 0xFC, 0]) + name.encode().ljust(13, b"\n")
    b[72:90] = bytes([0, 0, 0, 0xFD, 0, 48, max_hz, 30, 160, 60]) + bytes(8)
    return bytes(b)


def gpu(**kw):
    g = {"card": "card1", "addr": "0000:01:00.0", "vendor": "nvidia", "name": "GeForce RTX 4070", "codename": "",
         "maker": "ASUS", "driver": "nvidia", "boot_vga": True, "vram": 12 * GiB, "vram_used": 1 * GiB, "busy": 3,
         "link": {"gen": 4, "width": 16, "max_gen": 4, "max_width": 16, "slot_gen": 4, "slot_width": 16},
         "nvidia": None, "apps": [], "bar1": None, "integrated": False}
    g.update(kw)
    return g


def computer(**over):
    """A healthy 2022 desktop; tests break one thing at a time."""
    f = {"time": 0, "sudo": False,
         "os": {"name": "Ubuntu 24.04 LTS", "kernel": "6.8.0", "arch": "x86_64", "host": "pc", "uptime": 3600,
                "session": "wayland", "desktop": "GNOME", "virt": "none"},
         "board": {"vendor": "ASUS", "product": "System Product Name", "board_vendor": "ASUSTeK", "board": "PRIME B660-PLUS",
                   "bios_vendor": "AMI", "bios_version": "3010", "bios_date": "03/15/2025", "chassis": 3,
                   "uefi": True, "secure_boot": True, "tpm": "2"},
         "cpu": {"model": "12th Gen Intel(R) Core(TM) i5-12400F", "vendor": "GenuineIntel", "arch": "x86_64", "cores": 6,
                 "threads": 12, "sockets": 1, "max_mhz": 4400.0, "min_mhz": 800.0, "base_mhz": 2500.0, "cur_mhz": [800, 4400],
                 "l2": "7.5 MiB (6 instances)", "l3": "18 MiB (1 instance)", "virt": "VT-x",
                 "flags": ["aes", "avx", "avx2", "ht", "lm", "vmx"], "governor": "powersave", "epp": "balance_performance",
                 "driver": "intel_pstate", "microcode": "0x35", "smt": "on", "p_cores": None, "e_cores": None, "kvm": True},
         "memory": {"total": 31 * GiB, "available": 20 * GiB, "swap_total": 2 * GiB, "swap_used": 0, "zram": 0, "slots": 4,
                    "max_capacity": 128 * GiB,
                    "dimms": [{"size": 16 * GiB, "type": "DDR4", "speed": 3200, "configured": 3200, "maker": "Kingston",
                               "part": "KF432C16BB/16", "slot": s, "form": "DIMM", "ecc": False} for s in ("A2", "B2")]},
         "disks": [{"name": "nvme0n1", "model": "Samsung SSD 980", "size": 1000204886016, "kind": "nvme", "tran": "nvme",
                    "system": True, "mounts": [("/", 200e9, 980e9)], "trim": "enabled", "health": None,
                    "link": {"gen": 3, "width": 4, "max_gen": 3, "max_width": 4, "slot_gen": 4, "slot_width": 4}}],
         "gpus": [gpu()],
         "displays": [{"card": "card1", "port": "DP 1", "name": "LG ULTRAGEAR", "max_hz": 60, "mode": "2560x1440", "internal": False}],
         "battery": [], "net": [{"name": "enp3s0", "kind": "ethernet", "model": "Intel I225-V", "driver": "igc", "up": True, "speed": 1000}]}
    for path, value in over.items():
        node = f
        *head, last = path.split(".")
        for k in head:
            node = node[int(k)] if isinstance(node, list) else node[k]
        node[int(last) if isinstance(node, list) else last] = value
    return f


def found(facts, part=None):
    return [i["text"] for s in sysinfo.build(facts, [part] if part else None) for i in s["insights"]]


class Parsers(unittest.TestCase):
    def test_memory_sticks_and_empty_slots(self):
        slots, cap, dimms = hardware.parse_udev_memory(UDEV)
        self.assertEqual((slots, cap // GiB, len(dimms)), (2, 64, 1))
        self.assertEqual((dimms[0]["speed"], dimms[0]["configured"], dimms[0]["part"]), (3200, 2400, "KF432C16BB/8"))
        self.assertFalse(dimms[0]["ecc"])

    def test_edid_name_and_refresh(self):
        self.assertEqual(hardware.parse_edid(edid("DELL S2721DGF", 165)), {"name": "DELL S2721DGF", "max_hz": 165})
        self.assertEqual(hardware.parse_edid(b"junk"), {"name": "", "max_hz": None})

    def test_small_parsers(self):
        self.assertEqual(hardware.marketing_name("GA102 [GeForce RTX 3090 Ti]"), "GeForce RTX 3090 Ti")
        self.assertEqual(hardware.pcie_gen("16.0 GT/s PCIe"), 4)
        self.assertEqual(hardware.pcie_gen("8.0 GT/s PCIe"), 3)
        self.assertEqual(hardware.parse_lscpu("Model name:  Intel(R) Core(TM) i7-6700 CPU @ 3.40GHz\nCPU(s): 8")["CPU(s)"], "8")
        smi = "GPU 00000000:01:00.0\n    BAR1 Memory Usage\n        Total : 256 MiB\n        Used : 2 MiB\n"
        self.assertEqual(hardware.parse_nvidia_bar1(smi), {"0000:01:00.0": 256})
        self.assertEqual(hardware._short_vendor("Micro-Star International Co., Ltd. [MSI]"), "MSI")

    def test_generations(self):
        self.assertEqual(sysinfo.cpu_generation("Intel(R) Core(TM) i7-6700 CPU @ 3.40GHz"), ("6th gen", 2015))
        self.assertEqual(sysinfo.cpu_generation("13th Gen Intel(R) Core(TM) i9-13900K"), ("13th gen", 2022))
        self.assertEqual(sysinfo.cpu_generation("Intel(R) Core(TM) Ultra 7 155H"), ("Core Ultra series 1", 2023))
        self.assertEqual(sysinfo.cpu_generation("AMD Ryzen 7 5800X 8-Core Processor")[1], 2020)
        self.assertEqual(sysinfo.cpu_generation("ARM Cortex-A72"), (None, None))
        self.assertEqual(sysinfo.cpu_name("AMD Ryzen 7 5800X 8-Core Processor"), "AMD Ryzen 7 5800X")
        self.assertEqual(sysinfo.cpu_name("Intel(R) Core(TM) i7-6700 CPU @ 3.40GHz"), "Intel Core i7-6700")
        self.assertEqual(sysinfo.gpu_year("NVIDIA GeForce RTX 4090"), 2022)
        self.assertEqual(sysinfo.ai_model_size(24 * GiB), 32)
        self.assertEqual(sysinfo.ai_model_size(8 * GiB), 8)
        self.assertIsNone(sysinfo.ai_model_size(2 * GiB))

    def test_sizes_read_like_the_label(self):
        self.assertEqual(sysinfo.disk_size(512110190592), "512 GB")
        self.assertEqual(sysinfo.disk_size(2000398934016), "2 TB")
        self.assertEqual(sysinfo.gb(32 * GiB), "32 GB")

    def test_parts_by_any_name(self):
        self.assertEqual(sysinfo.resolve(["gpu", "RAM", "bios"]), (["memory", "graphics", "board"], []))
        self.assertEqual(sysinfo.resolve(["toaster"])[1], ["toaster"])


class WorthKnowing(unittest.TestCase):
    def test_a_healthy_computer_has_little_to_say(self):
        self.assertEqual(found(computer()), [])
        who, line = sysinfo.headline(computer())
        self.assertIn("Intel Core i5-12400F", line)
        self.assertIn("32 GB RAM DDR4", line)   # the sticks, not the kernel's 31

    def test_every_row_teaches_something(self):
        for s in sysinfo.build(computer()):
            for r in s["rows"]:
                self.assertTrue(r["note"] and r["value"], r)

    def test_monitor_in_the_motherboard(self):
        f = computer()
        f["gpus"].insert(0, gpu(card="card0", vendor="intel", name="AlderLake-S GT1", integrated=True, vram=None, link=None))
        f["displays"][0]["card"] = "card0"
        self.assertIn("The monitor is plugged into the motherboard, not the graphics card", found(f, "graphics"))
        f["board"]["chassis"] = 10   # a laptop: the screen is wired where it is
        self.assertEqual([t for t in found(f, "graphics") if "plugged" in t], [])

    def test_graphics_card_troubles(self):
        self.assertTrue(any("isn't using NVIDIA's driver" in t for t in found(computer(**{"gpus.0.driver": "nouveau"}))))
        lanes = {"gen": 4, "width": 8, "max_gen": 4, "max_width": 16, "slot_gen": 4, "slot_width": 16}
        self.assertTrue(any("x8 lanes instead of x16" in t for t in found(computer(**{"gpus.0.link": lanes}))))
        self.assertTrue(any("sits in an x4 slot" in t for t in found(computer(**{"gpus.0.link": dict(lanes, width=4, slot_width=4)}))))
        self.assertIn("Resizable BAR is off", found(computer(**{"gpus.0.bar1": 256}), "graphics"))
        old = computer(**{"cpu.model": "Intel(R) Core(TM) i7-6700 CPU @ 3.40GHz", "gpus.0.bar1": 256})
        self.assertNotIn("Resizable BAR is off", found(old))           # too old to support it: no tip to chase
        self.assertTrue(any("years older than the GeForce RTX 4070" in t for t in found(old)))
        self.assertTrue(any("up to 165 Hz" in t for t in found(computer(**{"displays.0.max_hz": 165}))))

    def test_memory(self):
        one = computer()
        one["memory"]["dimms"] = one["memory"]["dimms"][:1]
        self.assertIn("One memory stick: it runs in single channel", found(one))
        self.assertTrue(any("rated for 3200" in t for t in found(computer(**{"memory.dimms.0.configured": 2133}))))
        short = computer(**{"memory.swap_used": 12 * GiB})
        self.assertTrue(any("Memory runs short" in t for t in found(short)))
        detail = next(i["detail"] for s in sysinfo.build(short) for i in s["insights"])
        self.assertIn("2 free slots", detail)

    def test_storage(self):
        f = computer(**{"disks.0.kind": "hdd", "disks.0.link": None})
        self.assertIn("Ubuntu runs from a hard drive", found(f))
        worn = computer(**{"disks.0.health": {"used_pct": 85, "hours": 20000, "written": 300e12}})
        self.assertTrue(any("85% of its rated life" in t for t in found(worn)))
        self.assertTrue(any("could go faster" in t for t in found(computer(**{"disks.0.link": {
            "gen": 3, "width": 4, "max_gen": 4, "max_width": 4, "slot_gen": 3, "slot_width": 4}}))))
        rows = [r["label"].strip() for s in sysinfo.build(computer(**{"disks.0.mounts": [("/media/me/storage", 1e9, 1e12)]})) for r in s["rows"]]
        self.assertIn("storage", rows)

    def test_cpu_board_battery_network(self):
        self.assertIn("No AVX2: some modern programs won't run", found(computer(**{"cpu.flags": ["avx", "lm", "vmx"]})))
        self.assertIn("Virtualization is off", found(computer(**{"cpu.flags": ["avx", "avx2"], "cpu.virt": ""})))
        self.assertIn("Secure Boot is off", found(computer(**{"board.secure_boot": False})))
        self.assertTrue(any("firmware dates from 2016" in t for t in found(computer(**{"board.bios_date": "05/19/2016"}))))
        bat = computer(battery=[{"name": "BAT0", "maker": "", "model": "", "tech": "Li-ion", "status": "Discharging",
                                 "charge": 50, "health": 55, "cycles": 900, "wh": 57.0}])
        self.assertTrue(any("holds only 55%" in t for t in found(bat)))
        self.assertTrue(any("only 100 Mb/s" in t for t in found(computer(**{"net.0.speed": 100}))))

    def test_no_false_alarms(self):
        laptop = computer(**{"board.chassis": 10, "gpus.0.link": {"gen": 4, "width": 8, "max_gen": 4, "max_width": 16,
                                                                    "slot_gen": 4, "slot_width": 8}})
        self.assertEqual(found(laptop), [])      # laptops wire their graphics at x8 on purpose
        vm = computer(**{"os.virt": "kvm", "disks.0.kind": "hdd", "disks.0.link": None})
        self.assertNotIn("Ubuntu runs from a hard drive", found(vm))
        who, _ = sysinfo.headline(computer())
        self.assertEqual(who, "ASUS desktop")    # 'System Product Name' is a placeholder, not a model
        full = computer(**{"memory.available": GiB})
        self.assertIn("Memory is almost full right now", found(full))
        unknown_slot = {"gen": 3, "width": 4, "max_gen": 4, "max_width": 4, "slot_gen": None, "slot_width": None}
        self.assertEqual(found(computer(**{"disks.0.link": unknown_slot}), "storage"), [])   # no guess, no crash

    def test_one_broken_part_keeps_the_rest(self):
        f = computer()
        f["memory"] = {"total": "lots"}   # garbage from a strange machine
        keys = [s["key"] for s in sysinfo.build(f)]
        self.assertIn("cpu", keys)
        self.assertIn("graphics", keys)


class ThisComputer(unittest.TestCase):
    def test_command_runs_here(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(main(["sysinfo", "--json", "--no-sudo"]), 0)
        data = json.loads(out.getvalue())
        self.assertTrue(data["sections"])
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(main(["sysinfo", "cpu", "explain", "--no-sudo"]), 0)
        self.assertIn("PROCESSOR", out.getvalue())
        self.assertEqual(main(["sysinfo", "toaster"]), 2)


if __name__ == "__main__":
    unittest.main()
