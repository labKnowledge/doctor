"""Plain-language explanations from Claude, run read-only: it may look around the system but never change it."""
import json, os, shutil, subprocess, time

# Files that are none of its business, even read-only.
SECRETS = ["Read(~/.ssh/**)", "Read(**/.env*)", "Read(**/*credentials*)", "Read(**/*secret*)", "Read(~/.gnupg/**)",
           "Read(/etc/shadow)", "Read(**/*.pem)", "Read(**/*.key)", "Grep(~/.ssh/**)", "Grep(**/.env*)"]

# Commands the agent may run to investigate. Anything else is refused without asking (dontAsk mode).
READ_ONLY = [
    "journalctl", "systemctl status", "systemctl show", "systemctl cat", "systemctl list-units", "systemctl list-unit-files",
    "systemctl is-active", "systemctl is-enabled", "systemctl --user status", "systemctl --user show", "systemctl --user cat",
    "systemctl --user list-units", "systemd-analyze", "coredumpctl list", "coredumpctl info", "ss", "ps", "free", "df", "du",
    "lsblk", "findmnt", "uptime", "uname", "lscpu", "lsusb", "lspci", "ip addr", "ip route", "ip link", "resolvectl status",
    "nvidia-smi", "sensors", "docker ps", "docker logs", "docker inspect", "docker stats --no-stream", "docker system df",
    "snap list", "snap changes", "snap tasks", "snap services", "apt list", "apt-cache policy", "dpkg -l", "dpkg -S",
    "lpstat", "mmcli -L", "bluetoothctl devices", "ls", "stat", "wc", "file", "which",
]

SYSTEM = """You are the assistant inside `doctor`, a diagnose-and-fix tool on the user's own Ubuntu desktop.
The user is not a Linux expert. Explain in plain language, like a calm, sharp technician:
- what it is and what it means for them (one or two sentences),
- whether it matters (be honest: "harmless", "worth fixing", "fix now"),
- what to do. If the issue has a fix number, recommend it by number (e.g. "type f 4"), or say why to skip it.
Facts that save you searching: low-memory app kills are logged by systemd-oomd (journalctl -u systemd-oomd), kernel
OOM kills in journalctl -k; the report already holds most answers, so check it before running anything.
Disk full? `doctor clean` clears caches that rebuild themselves; `doctor deep [system|storage|folder]`
lists big things safe to remove and `doctor pick 1 3` deletes them (in interactive mode: clean, deep, pick).
You may run read-only commands to check facts before answering; keep it to a few. You cannot change anything,
so never tell the user you did. You don't remember past conversations, so don't
offer to follow up later; tell them what to run or look at instead (e.g. "run doctor right after it happens"). Under 150 words. No headings, no tables; short paragraphs or a few bullets."""


def available():
    return not os.environ.get("DOCTOR_NO_AGENT") and shutil.which("claude") is not None


HOW_TO_FIX = {
    "interactive": "The user is in doctor's interactive mode: they apply a fix by typing f followed by the ISSUE number (f 4).",
    "cli": "The user is on the command line: they apply a fix with `doctor fix N`, where N is the FIX number shown as [fix N]; "
           "it differs from the issue number. Always write the whole command, e.g. `doctor fix 4`, never just f 4.",
}


def header(mode):
    return f"Today is {time.strftime('%A %Y-%m-%d %H:%M')}. {HOW_TO_FIX[mode]}\n\n"


def condensed(report, limit=40):
    """The report as compact text: enough context, few tokens."""
    lines = []
    for n, f in enumerate(report.get("issues") or report["findings"], 1):
        fx = f" [fix {f['fix'].get('n', '')}: {f['fix']['label']}]" if f.get("fix") else ""
        lines.append(f"{n}. ({f['level']}, {f['area']}) {f['title']}{fx}")
        lines += [f"     {d[:160]}" for d in f["detail"][:3]]
    passing = [f["title"] for f in report["findings"] if f["level"] == "ok"]
    if passing:
        lines.append("Passing checks: " + "; ".join(passing))
    return "\n".join(lines[:limit * 4] + lines[-1:] if passing and len(lines) > limit * 4 else lines)


def explain_prompt(n, finding, report, mode="interactive"):
    fx = finding.get("fix")
    return (header(mode) + f"Explain issue {n} from the user's doctor report.\n\n"
            f"Issue {n}: ({finding['level']}, {finding['area']}) {finding['title']}\n"
            + "\n".join(f"  {d}" for d in finding["detail"]) +
            (f"\n  Offered fix {fx.get('n', '')} ({'safe' if fx['safe'] else 'review first'}): {fx['label']}\n  It runs:\n"
             + "\n".join(f"    $ {l}" for l in fx["cmd"].splitlines()) if fx else "\n  No automatic fix is offered.") +
            f"\n\nRest of the report for context:\n{condensed(report)}")


def ask_prompt(question, report, mode="interactive"):
    return header(mode) + f"The user asks: {question}\n\nTheir latest doctor report (issue numbers match what they see):\n{condensed(report)}"


def process_prompt(d, question=None, mode="interactive"):
    """A running process: what it is, why it runs, whether ending it is safe."""
    ask = (f"The user asks about this running process: {question}" if question else
           "Explain this running process: what it is, why it's probably running, and whether it's safe to end "
           "(what would close or stop, whether it comes back by itself). In interactive mode they end it with k, "
           "force it with f, or end the whole app with a.")
    facts = (f"Process {d['name']} (PID {d['pid']}), using {d['rss'] >> 20} MB RAM, {d['threads']} threads, state {d['state']}.\n"
             f"Started by: {d['parent']} (PID {d['ppid']}). Belongs to: {d['unit'] or 'nothing in particular'}"
             f"{' (one of the user' + chr(39) + 's own units)' if d['user_unit'] else ''}, {d['group']} process(es) in it.\n"
             f"Command: {d['cmd'][:600]}" + (f"\nWarning already shown to the user: {d['warning']}" if d["warning"] else ""))
    return header(mode) + ask + "\n\n" + facts


def service_prompt(unit, user, status, log, question=None, mode="interactive"):
    """A service: what it does, whether this computer needs it, and what the log says."""
    ask = (f"The user asks about the service {unit}: {question}" if question else
           f"Explain the service {unit}: what it does, whether a typical desktop needs it, whether anything in its status "
           "or log is a problem, and what to do. In interactive mode they act on it with r restart, s stop, t start, "
           "d disable (off now and at boot), e enable.")
    return (header(mode) + ask + f"\n\nIt is a {'user' if user else 'system'} service. Status:\n{status[:1500]}"
            f"\n\nRecent log:\n{log[-2500:]}")


def row_prompt(screen, about, row, note="", mode="interactive"):
    """One row of a Look closer screen (a port, a sensor, a startup item, a log line...): explain it to a non-expert."""
    return (header(mode) + f"The user is on doctor's '{screen}' screen ({about}) and selected this row:\n  {row}\n"
            + (f"doctor's one-line note about it: {note}\n" if note else "")
            + "Explain what it is, whether it is normal on a desktop, whether anything needs doing, and what. Check facts "
              "on the system first if useful (one or two read-only commands).")


def stream(prompt, on_text, on_tool, cwd):
    """Run Claude read-only and stream its answer. Returns an error message, or "" on success."""
    argv = ["claude", "-p", "--output-format", "stream-json", "--verbose", "--include-partial-messages",
            "--no-session-persistence", "--strict-mcp-config", "--setting-sources", "", "--model", "sonnet",
            "--permission-mode", "dontAsk", "--tools", "Bash,Read,Grep,Glob",
            "--allowedTools", "Read", "Grep", "Glob", *[f"Bash({c}:*)" for c in READ_ONLY],
            "--disallowedTools", *SECRETS, "--append-system-prompt", SYSTEM, "--", prompt]
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace", cwd=cwd)
    except OSError as e:
        return str(e)
    got_text = False
    try:
        for line in proc.stdout:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if ev.get("type") == "stream_event":
                d = ev.get("event", {}).get("delta", {})
                if d.get("type") == "text_delta":
                    on_text(d["text"])
                    got_text = True
            elif ev.get("type") == "assistant":
                for block in ev.get("message", {}).get("content", []):
                    if block.get("type") == "tool_use":
                        inp = block.get("input", {})
                        on_tool(inp.get("command") or inp.get("file_path") or inp.get("pattern") or block.get("name"))
            elif ev.get("type") == "result" and ev.get("is_error"):
                return ev.get("result") or "the assistant failed"
    except KeyboardInterrupt:
        proc.kill()
        return "stopped"
    proc.wait()
    if proc.returncode and not got_text:
        err = (proc.stderr.read() or "").strip().splitlines()
        return err[-1] if err else f"claude exited with {proc.returncode}"
    return ""
