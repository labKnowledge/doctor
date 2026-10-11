"""Processes: what runs, what it belongs to, and ending it safely. Data and actions only; the screen is in interactive.py."""
import os, re, signal, subprocess, time

from .core import read
from .health import app_name

# Ending one of these breaks the desktop session, sound, or the system itself. Asked about with a plain warning.
SESSION = re.compile(r"^(gnome-shell|Xorg|Xwayland|gnome-session.*|systemd|dbus-daemon|dbus-broker|pipewire.*|wireplumber|"
                     r"lightdm|gdm.*|sshd|NetworkManager|polkitd|snapd|containerd|dockerd)$")
WHY = {"gnome-shell": "this is your desktop: ending it closes every window and may log you out",
       "Xorg": "this draws your screen: ending it logs you out", "Xwayland": "older apps' windows would close",
       "pipewire": "sound would stop until it restarts", "wireplumber": "sound would stop until it restarts",
       "sshd": "remote logins to this computer would stop", "NetworkManager": "you would lose the network",
       "dockerd": "every Docker container would stop", "containerd": "every Docker container would stop"}


def unit_of(pid):
    """The systemd unit (app scope or service) a process lives in, and whether it's one of the user's own."""
    for line in read(f"/proc/{pid}/cgroup").splitlines():
        path = line.split(":", 2)[-1]
        if path and path != "/":
            unit = path.rstrip("/").split("/")[-1]
            return unit, "/user@" in path
    return "", False


def processes(ctx, sort="mem", limit=15):
    """The biggest (sort="mem") or busiest (sort="cpu") processes: [{pid, user, cpu, rss, running, name, app, mine}]."""
    rows = []
    me = os.getpid()
    out = ctx.run(f"ps -eo pid,user:16,pcpu,rss,etime,comm --no-headers --sort={'-rss' if sort == 'mem' else '-pcpu'}")
    for line in out.splitlines():
        p = line.split(None, 5)
        if len(p) < 6 or int(p[0]) == me or p[3] == "0":   # rss 0: kernel threads, nothing to end
            continue
        unit, _ = unit_of(p[0])
        rows.append({"pid": int(p[0]), "user": p[1], "cpu": float(p[2]), "rss": int(p[3]) * 1024, "running": p[4],
                     "name": p[5].strip(), "app": app_name(unit) if unit else "", "mine": p[1] == ctx.user})
        if len(rows) >= limit:
            break
    return rows


def detail(pid):
    """Everything worth knowing before ending a process. None if it's already gone."""
    status = read(f"/proc/{pid}/status")
    if not status:
        return None
    st = dict(l.split(":", 1) for l in status.splitlines() if ":" in l)
    if st.get("State", "").strip().startswith("Z"):
        return None   # finished; only waiting for its parent to notice
    cmd = read(f"/proc/{pid}/cmdline").replace("\0", " ").strip()
    ppid = int(st.get("PPid", "0").strip() or 0)
    unit, user_unit = unit_of(pid)
    group = [int(x) for x in read(f"/sys/fs/cgroup{_cgroup_path(pid)}/cgroup.procs").split() if x.isdigit()]
    name = st.get("Name", "").strip()
    return {"pid": pid, "name": name, "cmd": cmd or f"[{name}]", "state": st.get("State", "").strip(),
            "rss": int(st.get("VmRSS", "0 kB").split()[0]) * 1024, "threads": int(st.get("Threads", "1").strip()),
            "uid": int(st.get("Uid", "0").split()[0]), "parent": read(f"/proc/{ppid}/comm").strip() if ppid else "",
            "ppid": ppid, "unit": unit, "user_unit": user_unit, "app": app_name(unit) if unit else "",
            "group": len(group), "warning": risk(pid, name),
            "has_doctor": os.getpid() in group or os.getppid() in group}   # ending the whole group would end doctor too


def _cgroup_path(pid):
    for line in read(f"/proc/{pid}/cgroup").splitlines():
        return line.split(":", 2)[-1]
    return "/"


def risk(pid, name):
    """A plain-words warning when ending this would hurt, or "" when it's an ordinary app."""
    if pid == 1:
        return "this is the system itself; it can't be ended"
    if pid in (os.getpid(), os.getppid()):
        return "this is doctor (or the terminal it runs in)"
    if SESSION.match(name):
        return WHY.get(name.split("-")[0] if name.startswith("pipewire") else name, "the system or your session depends on it")
    return ""


def end(pid, force=False, wait=3.0):
    """Ask a process to close (SIGTERM), or force it (SIGKILL). Returns "ended", "still running", "gone" or "needs sudo"."""
    try:
        os.kill(pid, signal.SIGKILL if force else signal.SIGTERM)
    except ProcessLookupError:
        return "gone"
    except PermissionError:
        return "needs sudo"
    return _wait(pid, wait)


def end_as_root(pid, force=False, wait=3.0):
    """Same, through sudo (asks for the password in the terminal)."""
    r = subprocess.run(["sudo", "kill", "-KILL" if force else "-TERM", str(pid)])
    return _wait(pid, wait) if r.returncode == 0 else "not ended"


def end_group(unit, user_unit):
    """End a whole app (every process in its scope) or stop a service. Returns the command's exit code."""
    cmd = ["systemctl", "--user", "stop", unit] if user_unit else ["sudo", "systemctl", "stop", unit]
    return subprocess.run(cmd).returncode


def _wait(pid, wait):
    end_at = time.time() + wait
    while time.time() < end_at:
        if not os.path.exists(f"/proc/{pid}") or read(f"/proc/{pid}/stat").split(") ")[-1][:1] == "Z":
            return "ended"
        time.sleep(0.1)
    return "still running"
