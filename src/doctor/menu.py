"""A keyboard menu for the terminal: arrows move, Enter opens, a letter jumps straight to its entry.
Stdlib only. Falls back to "type the letter" when the terminal can't redraw (too short, or not a terminal)."""
import os, re, select, shutil, sys, textwrap

UP, DOWN, ENTER, BACK, QUIT = "up", "down", "enter", "back", "quit"
PGUP, PGDN, HOME, END = "pgup", "pgdn", "home", "end"
KEYS = {b"\x1b[5~": PGUP, b"\x1b[6~": PGDN, b"\x1b[H": HOME, b"\x1b[F": END, b"\x1bOH": HOME, b"\x1bOF": END,
        b"\x1b[A": UP, b"\x1bOA": UP, b"\x1b[B": DOWN, b"\x1bOB": DOWN, b"\t": DOWN, b"\x1b[Z": UP,
        b"\r": ENTER, b"\n": ENTER, b"\x1b": BACK, b"\x7f": BACK, b"\x03": QUIT}
ANSI = re.compile(r"\x1b\[[\d;]*m")


def visible(s):
    return len(ANSI.sub("", s))


class Raw:
    """Read single keys without Enter or echo. Signals stay on, so Ctrl+X (doctor's quit key) still works."""

    def __enter__(self):
        import termios
        self.fd = sys.stdin.fileno()
        self.saved = termios.tcgetattr(self.fd)
        mode = termios.tcgetattr(self.fd)
        mode[3] &= ~(termios.ICANON | termios.ECHO)
        mode[6][termios.VMIN], mode[6][termios.VTIME] = 1, 0
        termios.tcsetattr(self.fd, termios.TCSANOW, mode)
        sys.stdout.write("\x1b[?25l")   # hide the cursor while choosing
        sys.stdout.flush()
        return self

    pending = None

    def key(self, timeout=None):
        """One key press, or None when `timeout` seconds pass without one."""
        if self.pending:
            b, self.pending = self.pending, None
            return KEYS.get(b) or b.decode(errors="ignore")
        if timeout and not select.select([self.fd], [], [], timeout)[0]:
            return None
        b = os.read(self.fd, 1)
        if b == b"\x1b" and select.select([self.fd], [], [], 0.03)[0]:
            nxt = os.read(self.fd, 1)
            if nxt not in (b"[", b"O"):
                self.pending = nxt          # Esc, then a separate key typed quickly: keep that key
                return BACK
            b += nxt
            while select.select([self.fd], [], [], 0.03)[0]:   # the rest of an arrow / PgUp / Home sequence
                ch = os.read(self.fd, 1)
                b += ch
                if ch.isalpha() or ch == b"~":
                    break
        return KEYS.get(b) or (b.decode(errors="ignore") if len(b) == 1 else "")

    def __exit__(self, *exc):
        import termios
        sys.stdout.write("\x1b[?25h")
        sys.stdout.flush()
        termios.tcsetattr(self.fd, termios.TCSANOW, self.saved)


def flush_input():
    """Throw away keys typed ahead, so they can't answer a question (or a password prompt) nobody has seen yet."""
    try:
        import termios
        termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
    except Exception:
        pass


def can_redraw(lines):
    size = shutil.get_terminal_size((0, 0))
    return sys.stdin.isatty() and sys.stdout.isatty() and size.lines > lines + 1 and size.columns >= 60


def fit(line, width):
    """Cut a coloured line to the terminal width so it never wraps (wrapping breaks the redraw)."""
    if visible(line) <= width:
        return line
    out, n = [], 0
    for part in re.split(r"(\x1b\[[\d;]*m)", line):
        if ANSI.fullmatch(part or "x"):
            out.append(part)
        else:
            out.append(part[:max(width - 1 - n, 0)])
            n += len(out[-1])
    return "".join(out) + "…\x1b[0m"


def choose(entries, render, extra_keys=(), start=0, refresh=None, with_index=False):
    """entries: [(key, ...)] that can be selected. render(selected_index) -> list of lines to show
    (selected_index is -1 when the terminal can't redraw: show no highlight and say "type a letter").
    Returns the chosen entry's key, one of extra_keys pressed, BACK or QUIT; with_index=True returns (that, selected index).
    refresh=N redraws every N seconds while waiting (live screens: render() fetches fresh data)."""
    if with_index:
        box = []
        key = choose(entries, lambda i: (box.append(i), render(i))[1], extra_keys, start, refresh)
        return key, (box[-1] if box and box[-1] >= 0 else start)
    keys = [e[0] for e in entries]
    sel = min(start, len(keys) - 1)
    lines = render(sel)
    if not can_redraw(len(lines)):
        print("\n".join(render(-1)))    # -1: nothing highlighted, the footer says to type the letter
        while True:
            try:
                a = input("› ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return QUIT
            if a in keys or a in extra_keys:
                return a
            if a in ("", "m", "back"):
                return BACK
            if a in ("q", "quit", "exit"):
                return QUIT
            print("  Type one of the letters shown.")
    width = shutil.get_terminal_size().columns - 1
    shown = 0
    try:
        with Raw() as raw:
            while True:
                lines = [fit(l, width) for l in render(sel)]
                if shown:
                    sys.stdout.write(f"\x1b[{shown}A\r\x1b[J")
                sys.stdout.write("\n".join(lines) + "\n")
                sys.stdout.flush()
                shown = len(lines)
                k = raw.key(refresh)
                if k is None:
                    continue
                if k == UP:
                    sel = (sel - 1) % len(keys)
                elif k == DOWN:
                    sel = (sel + 1) % len(keys)
                elif k == ENTER:
                    return keys[sel]
                elif k in (BACK, QUIT):
                    return k
                elif k.lower() in keys or k in extra_keys:
                    return k.lower() if k.lower() in keys else k
                elif k.lower() == "q":
                    return QUIT
    except KeyboardInterrupt:
        return QUIT


def pause(c, text="Enter back to the menu"):
    """After a screen of output: wait for one key. Returns QUIT if the user wants out."""
    print(c("2", f"\n  {text} · q quit"))
    if not (sys.stdin.isatty() and can_redraw(0)):
        try:
            return QUIT if input().strip().lower() in ("q", "quit") else BACK
        except (EOFError, KeyboardInterrupt):
            return QUIT
    try:
        with Raw() as raw:
            k = raw.key()
    except KeyboardInterrupt:
        return QUIT
    return QUIT if k in (QUIT, "q") else BACK


def key(prompt, flush=False):
    """Ask for one key press (no Enter needed). Returns the key, ENTER, BACK or QUIT; falls back to a typed line.
    flush=True first drops keys typed ahead (use it for yes/no questions)."""
    if flush:
        flush_input()
    sys.stdout.write(prompt)
    sys.stdout.flush()
    if not (sys.stdin.isatty() and can_redraw(0)):
        try:
            a = input().strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return QUIT
        return a.lower() if len(a) == 1 else (ENTER if not a else a)
    try:
        with Raw() as raw:
            k = raw.key()
    except KeyboardInterrupt:
        k = BACK
    print(k if len(k) == 1 and k.isprintable() else "")
    return k


class Column:
    """One column of a list screen: header, width, how to get the text from a row, right-aligned or not."""

    def __init__(self, header, width, get, right=False):
        self.header, self.width, self.get, self.right = header, width, get, right

    def cell(self, row):
        text = str(self.get(row))[:self.width]
        return f"{text:>{self.width}}" if self.right else f"{text:<{self.width}}"


def browse(c, title, about, load, columns, note=None, enter=None, actions=(), explain=None, learn=None,
           refresh=None, empty="Nothing to show.", footer_extra="", state=None):
    """A list you can move through: the selected row explains itself under the list (note), Enter acts on it,
    letters run actions, ? asks the assistant, o opens a Claude session about it (learn), / searches, r reloads, Esc back.

    load() -> rows (reloaded on r, after actions, and every `refresh` seconds). enter(row) and each action
    (key, label, fn(row)) may print; the screen waits for a key afterwards unless fn returns "quiet".
    A fn returning "menu" leaves with "menu" (the caller goes to its main menu). explain(row) streams an answer.
    Returns BACK, QUIT or "menu"."""
    state = state if state is not None else {}
    sel, top, find = state.get("sel", 0), 0, ""
    keys = {k: (label, fn) for k, label, fn in actions}
    fresh, loaded, first = True, [], True
    while True:
        if fresh:
            if first:
                sys.stdout.write(c("2", f"{title}: loading...") + "\r")
                sys.stdout.flush()
            loaded, fresh, first = load(), False, False
        rows = loaded
        if find:
            rows = [r for r in rows if find in " ".join(col.cell(r) for col in columns).lower()]
        if not can_redraw(12):
            return _browse_lines(c, title, about, rows, columns, note, enter, keys, explain, empty)
        size = shutil.get_terminal_size()
        width, room = size.columns - 1, max(size.lines - 13, 3)
        sel = max(0, min(sel, len(rows) - 1))

        def render():
            nonlocal top
            top = min(max(top, sel - room + 1), sel) if rows else 0
            head = "  ".join(f"{col.header:>{col.width}}" if col.right else f"{col.header:<{col.width}}" for col in columns)
            lines = [c("1", title) + c("2", f"  ·  {about}") + (c("36", f"   matching '{find}'") if find else ""), "",
                     c("2", f"     {head}")]
            if not rows:
                lines.append(f"     {empty if not find else 'Nothing matches.'}")
            for i in range(top, min(top + room, len(rows))):
                text = "  ".join(col.cell(rows[i]) for col in columns)
                lines.append(f"  {c('36;1', '›')}  {c('7', text)}" if i == sel else f"     {text}")
            more = len(rows) - min(top + room, len(rows))
            lines.append(c("2", f"     {'↑ ' + str(top) + ' more above' if top else ''}{'   ' if top and more else ''}"
                                f"{'↓ ' + str(more) + ' more below' if more else ''}"))
            explained = note(rows[sel]) if note and rows else ""
            wrapped = textwrap.wrap(explained, width - 6)[:3]
            lines += [c("36", "  ▸ ") + wrapped[0] if wrapped else ""] + [f"    {w}" for w in wrapped[1:]]
            acts = "".join(f" · {k} {label}" for k, (label, _) in keys.items())
            lines += ["", c("2", f"  ↑↓ move{' · Enter ' + enter[0] if enter and rows else ''}{acts}"
                                 f"{' · ? explain' if explain and rows else ''}{' · o learn more' if learn and rows else ''}"
                                 f" · / find · r refresh{footer_extra} · Esc back")]
            return [fit(l, width) for l in lines]
        action = None
        shown = 0
        try:
            with Raw() as raw:
                while action is None:
                    lines = render()
                    if shown:
                        sys.stdout.write(f"\x1b[{shown}A\r\x1b[J")
                    sys.stdout.write("\n".join(lines) + "\n")
                    sys.stdout.flush()
                    shown = len(lines)
                    k = raw.key(refresh)
                    if k is None:
                        action = "reload"
                    elif k == UP:
                        sel = max(sel - 1, 0)
                    elif k == DOWN:
                        sel = min(sel + 1, max(len(rows) - 1, 0))
                    elif k in (PGUP, PGDN):
                        sel = max(0, min(sel + (room if k == PGDN else -room), len(rows) - 1))
                    elif k in (HOME, END):
                        sel = 0 if k == HOME else max(len(rows) - 1, 0)
                    elif k == BACK:
                        if find:
                            find, action = "", "reload"
                        else:
                            return BACK
                    elif k in (QUIT, "q"):
                        return BACK
                    elif k == "m":
                        return "menu"
                    elif k in ("/", "r", "?") or (k == ENTER and enter) or k in keys or (k == "o" and learn):
                        action = k
        except KeyboardInterrupt:
            return BACK
        state["sel"] = sel
        if action in ("reload", "r"):
            fresh = action == "r" or bool(refresh)
            continue
        if action == "/":
            try:
                find = input(c("1", "  Find › ")).strip().lower()
            except (EOFError, KeyboardInterrupt):
                find = ""
            sel = 0
            continue
        if not rows:
            continue
        row = rows[sel]
        if action == "?":
            explain(row)
            result = None
        elif action == "o":
            learn(row)
            continue   # it opens in another window; this list stays
        else:
            result = (enter[1] if action == ENTER else keys[action][1])(row)
            fresh = True   # an action may have changed what the list shows
        if result == "menu":
            return "menu"
        if result != "quiet" and pause(c, "Enter back to the list") == QUIT:
            return QUIT


def _browse_lines(c, title, about, rows, columns, note, enter, keys, explain, empty):
    """The same screen for terminals that can't redraw: a numbered list, then typed commands."""
    print(c("1", f"\n{title}") + c("2", f"  ·  {about}"))
    if not rows:
        print(f"  {empty}")
    for n, r in enumerate(rows, 1):
        print(f"  {n:>3}  " + "  ".join(col.cell(r) for col in columns))
    acts = "".join(f" · {k} N {label}" for k, (label, _) in keys.items())
    print(c("2", f"\n  N {'= ' + enter[0] if enter else 'explains it'}{acts}{' · ? N explain' if explain else ''} · Enter back"))
    while True:
        try:
            a = input("› ").strip().split()
        except (EOFError, KeyboardInterrupt):
            return QUIT
        if not a:
            return BACK
        k, n = (a[0], a[1]) if len(a) > 1 else ("", a[0])
        if not n.isdigit() or not 1 <= int(n) <= len(rows):
            print("  A number from the list, or Enter to go back.")
            continue
        row = rows[int(n) - 1]
        if k == "?" and explain:
            explain(row)
        elif k in keys:
            if keys[k][1](row) == "menu":
                return "menu"
        elif not k and enter:
            if enter[1](row) == "menu":
                return "menu"
        elif note:
            print("  " + note(row))
