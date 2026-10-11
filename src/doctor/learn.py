"""Learn more: open a full Claude Code session in its own terminal window, already holding what the user was looking at,
set up to teach (how it works, how to see it yourself) rather than just answer. doctor keeps running in its own window.

The context goes into a small folder (prompt.md, system.txt, run.sh) under doctor's state, so a session can be
reopened later with: bash <folder>/run.sh"""
import os, re, shlex, shutil, subprocess, time

TUTOR = """The user opened this session from `doctor`, the system check-up tool on their own Ubuntu desktop, to understand
something better. They are not a Linux expert but want to learn. Be a patient, practical tutor:
- Start with a short, plain explanation of what it is and whether it matters for them.
- Then teach how it works underneath, a layer at a time, and show the read-only commands they can run to see it
  themselves (say what each command shows). Run them yourself when it helps, and explain the output.
- Offer to go deeper, or suggest a safe experiment.
Before changing anything on the system, explain what it would do and how to undo it, and wait for a clear yes.
Their files with secrets (~/.ssh, .env, keys, credentials) are none of your business."""

# Terminal programs and how to run a command in a new window of each.
TERMINALS = [
    ("gnome-terminal", lambda t, s: ["gnome-terminal", "--title", t, "--", "bash", s]),
    ("kgx", lambda t, s: ["kgx", "--title", t, "--", "bash", s]),
    ("ptyxis", lambda t, s: ["ptyxis", "--new-window", "--", "bash", s]),
    ("konsole", lambda t, s: ["konsole", "-p", f"tabtitle={t}", "-e", "bash", s]),
    ("kitty", lambda t, s: ["kitty", "--title", t, "bash", s]),
    ("alacritty", lambda t, s: ["alacritty", "-t", t, "-e", "bash", s]),
    ("wezterm", lambda t, s: ["wezterm", "start", "--", "bash", s]),
    ("tilix", lambda t, s: ["tilix", "-t", t, "-e", f"bash {shlex.quote(s)}"]),
    ("xfce4-terminal", lambda t, s: ["xfce4-terminal", "-T", t, "-x", "bash", s]),
    ("x-terminal-emulator", lambda t, s: ["x-terminal-emulator", "-e", "bash", s]),
    ("xterm", lambda t, s: ["xterm", "-T", t, "-e", "bash", s]),
]


def available():
    return not os.environ.get("DOCTOR_NO_AGENT") and shutil.which("claude") is not None


def prepare(state_dir, topic, facts, mode_hint=""):
    """Write the session's context and launcher. Returns the launcher script's path."""
    base = os.path.join(state_dir, "learn")
    slug = re.sub(r"[^a-z0-9]+", "-", topic.lower()).strip("-")[:40] or "topic"
    folder = os.path.join(base, time.strftime("%Y%m%d-%H%M%S-") + slug)
    os.makedirs(folder, mode=0o700, exist_ok=True)
    prompt = (f"I'm looking at this in doctor and want to understand it: {topic}\n\n"
              f"What doctor shows about it (gathered {time.strftime('%A %Y-%m-%d %H:%M')}):\n{facts.strip()}\n\n"
              "Explain it to me, then help me learn more." + (f"\n\n{mode_hint}" if mode_hint else ""))
    with open(os.path.join(folder, "prompt.md"), "w") as fh:
        fh.write(prompt)
    with open(os.path.join(folder, "system.txt"), "w") as fh:
        fh.write(TUTOR)
    script = os.path.join(folder, "run.sh")
    with open(script, "w") as fh:
        fh.write(f"""#!/bin/bash
# Reopen this learning session any time: bash {shlex.quote(script)}
cd {shlex.quote(folder)}
printf '\\033]0;%s\\007' {shlex.quote('Learn: ' + topic[:50])}
printf '\\033[1mdoctor · learning about:\\033[0m %s\\n\\n' {shlex.quote(topic)}
claude --append-system-prompt "$(cat system.txt)" "$(cat prompt.md)"
echo; read -r -p "Session over. Press Enter to close this window. " _
""")
    os.chmod(script, 0o700)
    for old in sorted(os.listdir(base))[:-30]:   # keep the last 30 sessions
        shutil.rmtree(os.path.join(base, old), ignore_errors=True)
    return script


def open_window(script, title):
    """Start the session in a new terminal window (or tmux window). Returns the terminal used, or "" if none could open."""
    if os.environ.get("TMUX") and shutil.which("tmux"):
        if subprocess.run(["tmux", "new-window", "-n", title[:20], "bash", script]).returncode == 0:
            return "tmux"
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return ""
    wanted = os.environ.get("TERMINAL", "")
    order = sorted(TERMINALS, key=lambda t: t[0] != os.path.basename(wanted))
    for name, argv in order:
        if shutil.which(name):
            try:
                subprocess.Popen(argv(title, script), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, start_new_session=True)
                return name
            except OSError:
                continue
    return ""
