"""Plain words for what the Look closer screens show: what a port, sensor, timing or log line means, and whether it
matters. Pure functions, no system access, so every screen teaches the same thing the same way."""
import re, time

PORTS = {
    22: "SSH, logging in to this computer remotely", 53: "DNS, turning names into addresses",
    67: "DHCP, handing out network addresses", 68: "DHCP, getting this computer its network address",
    80: "a web server", 111: "rpcbind, used for NFS file sharing", 123: "time sync (NTP)",
    139: "Windows file sharing (Samba)", 443: "a secure web server", 445: "Windows file sharing (Samba)",
    631: "printing (CUPS)", 1716: "phone link (GSConnect / KDE Connect)", 1900: "UPnP, devices finding each other",
    3000: "a development web server", 3306: "a MySQL database", 3389: "remote desktop (RDP)",
    5353: "mDNS, devices on your network finding each other", 5355: "LLMNR, local name lookups",
    5432: "a PostgreSQL database", 5900: "VNC remote desktop", 6379: "a Redis database", 7070: "AnyDesk remote access",
    8000: "a development web server", 8080: "a web server", 8443: "a secure web server", 9090: "a web admin console",
    11434: "Ollama, local AI models", 27017: "a MongoDB database",
}
REMOTE = {22, 3389, 5900, 7070}


def port(public, proto, number, program):
    what = PORTS.get(number) or ("a database" if 5400 < number < 5500 else "")
    what = f"Port {number} is {what}" if what else f"Port {number} belongs to {program.split(' (')[0] or 'an unnamed program'}"
    if not public:
        return f"{what}. Only programs on this computer can reach it, so it's safe."
    risk = (" Remote access: make sure you set this up on purpose." if number in REMOTE else
            " Databases shouldn't be open to the network; bind it to 127.0.0.1." if number in (3306, 5432, 6379, 27017) else "")
    return f"{what}. Other devices on your network can connect to it.{risk} Not yours? Enter shows the program; k ends it."


def sensor(chip, label, value):
    part = {"coretemp": "the CPU", "k10temp": "the CPU", "zenpower": "the CPU", "cpu": "the CPU",
            "nvme": "the SSD", "drivetemp": "a hard drive", "acpitz": "a motherboard sensor", "pch": "the chipset",
            "iwlwifi": "the Wi-Fi card", "amdgpu": "the graphics card", "nouveau": "the graphics card",
            "gpu": "the graphics card", "radeon": "the graphics card"}.get(chip.split("_")[0], f"the {chip} sensor")
    if "rpm" in value:
        rpm = int(re.sub(r"\D", "", value) or 0)
        return f"A fan ({label}). {'0 rpm is normal when it is cool: the fan rests.' if rpm == 0 else 'Spinning; louder usually means hotter or dustier.'}"
    if "GHz" in value:
        return "How fast the CPU cores run right now. Low when idle saves power; it rises when there's work."
    m = re.search(r"(-?\d+)°C", value)
    t = int(m.group(1)) if m else 0
    hot, warm = (70, 60) if part in ("the SSD", "a hard drive") else (90, 75)
    verdict = ("hot: check that the vents aren't blocked and the fans work" if t >= hot else
               "warm, fine under load, high if the computer is idle" if t >= warm else "a healthy temperature")
    return f"{label or 'Temperature'} of {part}: {t}°C is {verdict}."


def network(label, ms, loss):
    if ms is None:
        return {"router": "The router didn't answer: check Wi-Fi or the cable.",
                "DNS lookup": "Names couldn't be looked up: websites fail even though the connection works."}.get(
            label.split(" (")[0], "This step failed, so anything after it fails too.")
    good, slow = {"router": (5, 50), "DNS lookup": (60, 300), "HTTPS page load": (800, 3000)}.get(label.split(" (")[0], (60, 200))
    speed = "fast" if ms <= good else "fine" if ms <= slow else "slow"
    hint = {"router": "Slow or lossy here means Wi-Fi trouble: move closer or use a cable.",
            "DNS lookup": "Slow here makes every new website slow to start.",
            "HTTPS page load": "A whole secure page request, end to end."}.get(label.split(" (")[0], "Time to the internet and back.")
    return f"{ms:.0f} ms is {speed}{f', and {loss}% of tries got lost' if loss else ''}. {hint}"


def boot(secs, unit, user):
    name = unit.replace(".service", "")
    if unit.startswith(("apt-daily", "update-notifier", "fwupd", "man-db", "logrotate", "chkrootkit", "plocate", "e2scrub")):
        return f"{name} took {secs:.0f}s, but it's a background job: it doesn't hold up your desktop."
    if secs < 2:
        return f"{name} took {secs:.1f}s. Fast enough; nothing to do."
    return (f"{name} took {secs:.0f}s at startup. If you don't use it, turning it off (Enter, then d) makes startup "
            f"faster; ? tells you what it is first.")


def kill(when, who, why):
    if "(kernel)" in who:
        return (f"The kernel itself closed {who.replace(' (kernel)', '')} on {when}: memory ran out completely. "
                "Closing big apps or adding RAM prevents it.")
    return (f"systemd-oomd closed {who} on {when} because the computer spent {why.replace(' stalled', '')} of its time "
            "waiting for memory. It closes the biggest app to keep the rest responsive.")


def log(group):
    when = time.strftime("%H:%M", time.localtime(group["last"])) if group.get("last") else "?"
    often = "over and over: something is stuck in a loop" if group["count"] >= 100 else \
        "repeatedly" if group["count"] >= 5 else "once or twice: usually harmless if nothing seems broken"
    return f"{group['app']} logged this {often} (last at {when}): {group['sample']}"
