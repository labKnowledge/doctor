"""Run: python3 -m unittest discover -s tests   (no dependencies; read-only on the system, writes only to a temp folder)."""
import io, json, os, sys, tempfile, time, unittest
from contextlib import redirect_stdout
from pathlib import Path

TMP = tempfile.mkdtemp(prefix="doctor-test-")
os.environ["DOCTOR_DATA"] = TMP
os.environ["DOCTOR_NO_AGENT"] = "1"  # tests never call the assistant
os.environ["DOCTOR_NO_REFRESH"] = "1"  # tests never download vulnerability data
os.environ["DISK_CLEAN_DATA"] = os.path.join(TMP, "disk-clean")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from doctor import CHECKS, Ctx, run_checks  # noqa: E402
from doctor.cli import main, parse_numbers, render  # noqa: E402
from doctor.core import AREAS, RANK, finding, fix, normalize  # noqa: E402
from doctor.health import app_name  # noqa: E402
from doctor import vulns  # noqa: E402


def fake_report(findings):
    for n, f in enumerate([f for f in findings if f.get("fix")], 1):
        f["fix"]["n"] = n
    return {"time": time.time(), "took": 0.1, "host": "test", "sudo": False, "areas": AREAS, "findings": findings}


class Pure(unittest.TestCase):
    def test_parse_numbers(self):
        self.assertEqual(parse_numbers(["1", "3-5", "2,7"], 9), [1, 2, 3, 4, 5, 7])
        with self.assertRaises(ValueError):
            parse_numbers(["12"], 4)
        with self.assertRaises(ValueError):
            parse_numbers(["x"], 4)

    def test_app_names_are_human(self):
        base = "/user.slice/user-1000.slice/user@1000.service/app.slice/"
        self.assertEqual(app_name(base + "snap.code.code-be919d80-0850-470f-9765-45c18c0a3619.scope"), "VS Code")
        self.assertEqual(app_name(base + "app-gnome-google\\x2dchrome-799984.scope"), "Google Chrome")
        self.assertEqual(app_name(base + "app-org.gnome.Terminal.slice"), "Terminal")
        self.assertEqual(app_name(base + "jupyter-lab.service"), "jupyter-lab")

    def test_normalize_groups_repeats(self):
        self.assertEqual(normalize("restart counter is at 117"), normalize("restart counter is at 118"))

    def test_render_numbers_fixes_and_counts(self):
        r = fake_report([finding("crit", "Bad", ["why"], fix("Do it", "true", root=False)),
                         finding("warn", "Meh", [], fix("Maybe", "true", safe=False)),
                         finding("ok", "Fine")])
        for f in r["findings"]:
            f.update(area="memory", check="x")
        text = render(r)
        self.assertIn("1 problem(s)", text)
        self.assertIn("2. Maybe", text)
        self.assertIn("safe ones (1)", text)


class Live(unittest.TestCase):
    def test_every_check_runs_and_returns_valid_findings(self):
        results = run_checks(Ctx(use_sudo=False))
        self.assertTrue(results)
        names = {r["check"] for r in results}
        self.assertGreaterEqual(len(names), len(CHECKS) - 2)  # docker/gpu may be absent
        for r in results:
            self.assertIn(r["level"], RANK)
            self.assertTrue(r["title"])
            self.assertNotIn("could not run", r["title"], r)
            if r.get("fix"):
                self.assertTrue(r["fix"]["cmd"] and r["fix"]["label"])

    def test_fix_runs_chosen_user_fix_only(self):
        a, b = os.path.join(TMP, "a"), os.path.join(TMP, "b")
        r = fake_report([finding("warn", "A", [], fix("touch a", f"touch {a}", root=False)),
                         finding("warn", "B", [], fix("touch b", f"touch {b}", root=False, safe=False))])
        for f in r["findings"]:
            f.update(area="network", check="connectivity")
        with open(os.path.join(TMP, "last.json"), "w") as fh:
            json.dump(r, fh)
        with redirect_stdout(io.StringIO()) as out:
            code = main(["fix", "-y"])
        self.assertEqual(code, 0, out.getvalue())
        self.assertTrue(os.path.exists(a))
        self.assertFalse(os.path.exists(b), "unsafe fix must need an explicit number")
        with redirect_stdout(io.StringIO()):
            main(["fix", "2", "-y"])
        self.assertTrue(os.path.exists(b))

    def test_failed_fix_is_reported(self):
        r = fake_report([finding("warn", "A", [], fix("fails", "false\ntouch /nonexistent/x", root=False))])
        for f in r["findings"]:
            f.update(area="network", check="connectivity")
        with open(os.path.join(TMP, "last.json"), "w") as fh:
            json.dump(r, fh)
        with redirect_stdout(io.StringIO()) as out:
            code = main(["fix", "-y"])
        self.assertEqual(code, 1)
        self.assertIn("FAILED", out.getvalue())


    def test_fix_that_never_reports_done_counts_as_failed(self):
        r = fake_report([finding("warn", "A", [], fix("dies", "kill -9 $$", root=False))])
        for f in r["findings"]:
            f.update(area="network", check="connectivity")
        with open(os.path.join(TMP, "last.json"), "w") as fh:
            json.dump(r, fh)
        with redirect_stdout(io.StringIO()) as out:
            code = main(["fix", "-y"])
        self.assertEqual(code, 1, out.getvalue())
        self.assertIn("0 of 1", out.getvalue())


    def test_fix_is_verified_by_its_key(self):
        r = fake_report([finding("warn", "Gone after fixing", [], fix("noop", "true", root=False), key="test-gone")])
        for f in r["findings"]:
            f.update(area="network", check="connectivity")
        with open(os.path.join(TMP, "last.json"), "w") as fh:
            json.dump(r, fh)
        with redirect_stdout(io.StringIO()) as out:
            main(["fix", "-y"])
        self.assertIn("verified: fixed: Gone after fixing", out.getvalue())


class Vulnerabilities(unittest.TestCase):
    def test_match_keeps_versions_below_the_fix_and_unfixed_ones(self):
        cmp = lambda a, b: (a > b) - (a < b)
        rules = [["CVE-1", "foo", "2", 5.0], ["CVE-2", "foo", "1", 5.0], ["CVE-3", "bar", None, 9.8], ["CVE-4", "gone", "9", 1.0]]
        self.assertEqual([r[0] for r in vulns.match(rules, {"foo": "1", "bar": "3"}, cmp)], ["CVE-1", "CVE-3"])

    def test_version_compare_follows_debian_rules(self):
        for lo, hi in [("1.0~rc1", "1.0"), ("2.0", "1:0.1"), ("2.30-0ubuntu2", "2.30-0ubuntu10"), ("1.2", "1.2+esm1"),
                       ("7:6.1.1-3ubuntu5", "7:6.1.1-3ubuntu5+esm1"), ("1.0a", "1.0+")]:
            self.assertEqual((vulns.version_compare(lo, hi), vulns.version_compare(hi, lo)), (-1, 1), (lo, hi))
        self.assertEqual(vulns.version_compare("1.0", "1.0-0"), 0)

    def test_kev_counts_only_when_the_product_names_the_package(self):
        self.assertFalse(vulns.kev_matches("Oracle", "WebLogic Server", "openjdk-8-jre", "openjdk-8"))
        self.assertFalse(vulns.kev_matches("Mozilla", "Firefox", "libmozjs-115-0t64", "mozjs115"))
        self.assertTrue(vulns.kev_matches("Mozilla", "Firefox", "firefox", "firefox"))
        self.assertTrue(vulns.kev_matches("Linux", "Kernel", "linux-image-7.0.0-38-generic", "linux"))

    def test_reachable_and_exploited_ranks_first(self):
        row = lambda **k: {"kev": False, "epss": 0.01, "flags": 0, **k}
        exposed, idle, exploited = row(flags=7), row(epss=0.3), row(kev=True, flags=1)
        self.assertEqual(sorted([idle, exposed, exploited], key=vulns.score, reverse=True), [exploited, exposed, idle])
        self.assertTrue(vulns.worth_acting(exposed) and vulns.worth_acting(idle) and not vulns.worth_acting(row()))

    def test_hsi_level_is_the_highest_fully_passed(self):
        at = lambda lvl, ok: {"HsiLevel": lvl, "Flags": ["success"] if ok else []}
        self.assertEqual(vulns.hsi_level([at(1, True), at(1, False), at(2, True)]), 0)
        self.assertEqual(vulns.hsi_level([at(1, True), at(2, True), at(3, False)]), 2)

    def test_unsigned_installs_are_found_in_apt_history(self):
        hist = ("Start-Date: 2026-03-31  16:22:55\nCommandline: apt-get install -y --allow-unauthenticated asterisk "
                "asterisk-core-sounds-en-wav\nStart-Date: 2026-04-01  10:00:00\nCommandline: apt-get install vim\n")
        self.assertEqual(vulns.unsigned_installs(hist), [("2026-03-31", ["asterisk", "asterisk-core-sounds-en-wav"])])

    def test_check_without_data_says_it_is_downloading(self):
        if not vulns.release():
            self.skipTest("not Ubuntu")
        ctx = Ctx(use_sudo=False)
        ctx._cache.pop("vulns", None)
        titles = [f["title"] for f in vulns.vulnerabilities(ctx)]
        self.assertTrue(any("downloading in the background" in t for t in titles), titles)


class FreeSpace(unittest.TestCase):
    def test_deep_and_pick_through_doctor(self):
        """doctor deep FOLDER lists an idle project's build output; pick deletes only that."""
        proj = Path(tempfile.mkdtemp(dir=TMP)) / "old"
        (proj / "src").mkdir(parents=True)
        (proj / "package.json").write_text("{}")
        (proj / "node_modules").mkdir()
        (proj / "node_modules" / "blob").write_bytes(os.urandom(60 << 20))
        old = time.time() - 90 * 86400
        for p in (proj / "package.json", proj / "src", proj):
            os.utime(p, (old, old))
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(main(["deep", str(proj.parent)]), 0)
        self.assertIn("old: node_modules", out.getvalue())
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(main(["pick", "1"]), 0)
        self.assertIn("removed", out.getvalue())
        self.assertFalse((proj / "node_modules").exists())
        self.assertTrue((proj / "src").exists())

    def test_old_command_names_still_work(self):
        import subprocess
        link = os.path.join(TMP, "pick")
        os.symlink(Path(__file__).resolve().parent.parent / "bin/doctor", link)
        r = subprocess.run([link, "help"], capture_output=True, text=True)
        self.assertIn("disk-clean", r.stdout)


class Learn(unittest.TestCase):
    def test_session_opens_in_a_new_window_with_the_context(self):
        """o: the context lands in files (never on a command line), and a new terminal window runs the launcher."""
        import subprocess
        from doctor import learn
        bin_dir = os.path.join(TMP, "learn-bin")
        os.makedirs(bin_dir, exist_ok=True)
        for name, body in (("gnome-terminal", f'printf "%s\\n" "$@" > {TMP}/argv'),
                           ("claude", f'printf "%s" "$3" > {TMP}/prompt-seen')):
            with open(os.path.join(bin_dir, name), "w") as fh:
                fh.write(f"#!/bin/sh\n{body}\n")
            os.chmod(os.path.join(bin_dir, name), 0o755)
        env = {"PATH": bin_dir + os.pathsep + os.environ["PATH"], "DISPLAY": ":0", "TMUX": "", "TERMINAL": ""}
        old = {k: os.environ.get(k) for k in env}
        os.environ.update(env)
        try:
            script = learn.prepare(TMP, "Port 22", "note: $(touch /tmp/never) `x` \"q\"")
            self.assertEqual(learn.open_window(script, "Learn: Port 22"), "gnome-terminal")
            time.sleep(0.3)
            self.assertIn(script, open(os.path.join(TMP, "argv")).read())
            subprocess.run(["bash", script], input="\n", capture_output=True, text=True, env=os.environ)
            self.assertIn("$(touch /tmp/never)", open(os.path.join(TMP, "prompt-seen")).read())
            os.environ["DISPLAY"] = ""
            self.assertEqual(learn.open_window(script, "x"), "", "no desktop: doctor offers to run it here instead")
        finally:
            for k, v in old.items():
                os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


class Knowledge(unittest.TestCase):
    def test_rows_explain_themselves_in_plain_words(self):
        from doctor import knowledge as k
        self.assertIn("safe", k.port(False, "tcp", 5432, "postgres (12)"))
        self.assertIn("Remote access", k.port(True, "tcp", 22, "sshd (1)"))
        self.assertIn("bind it to 127.0.0.1", k.port(True, "tcp", 6379, "redis (9)"))
        self.assertIn("hot", k.sensor("coretemp", "Core 0", "95°C"))
        self.assertIn("healthy", k.sensor("nvme", "Composite", "40°C"))
        self.assertIn("fan rests", k.sensor("dell", "fan1", "0 rpm"))
        self.assertIn("Wi-Fi", k.network("router", 120, 10))
        self.assertIn("background job", k.boot(28, "chkrootkit.service", False))
        self.assertIn("kernel", k.kill("2026-10-10 02:59", "code (kernel)", "900 MB in RAM"))
        self.assertIn("loop", k.log({"app": "x", "count": 500, "sample": "boom", "last": 0}))


class Processes(unittest.TestCase):
    def test_end_asks_then_forces_a_stubborn_process(self):
        import subprocess
        from doctor import procs
        p = subprocess.Popen(["bash", "-c", "trap '' TERM; exec sleep 60"])
        time.sleep(0.3)
        d = procs.detail(p.pid)
        self.assertEqual(d["name"], "sleep")
        self.assertEqual(d["warning"], "")
        self.assertEqual(procs.end(p.pid, wait=0.5), "still running")
        self.assertEqual(procs.end(p.pid, force=True), "ended")
        p.wait()
        self.assertIsNone(procs.detail(p.pid))
        self.assertTrue(procs.risk(1, "systemd"))
        self.assertIn("desktop", procs.risk(1234, "gnome-shell"))
        self.assertEqual(procs.end(1), "needs sudo")


class Agent(unittest.TestCase):
    def test_prompt_carries_issue_fix_and_context(self):
        from doctor import agent
        f = finding("warn", "AnyDesk always on", ["port 7070"], fix("Turn off anydesk", "systemctl disable --now anydesk.service", safe=False))
        f.update(area="services", check="x")
        p = agent.explain_prompt(4, f, {"issues": [f], "findings": [f]})
        self.assertIn("Issue 4", p)
        self.assertIn("review first", p)
        self.assertIn("$ systemctl disable --now anydesk.service", p)

    def test_agent_is_read_only_and_kept_from_secrets(self):
        from doctor import agent
        self.assertFalse(any(c.split()[0] in ("rm", "kill", "sudo", "chmod", "tee", "cat") or
                             any(w in c.split() for w in ("restart", "stop", "enable", "disable", "start", "kill", "rm")) for c in agent.READ_ONLY))
        self.assertIn("Read(~/.ssh/**)", agent.SECRETS)
        self.assertFalse(agent.available())  # disabled for tests by DOCTOR_NO_AGENT


class Interactive(unittest.TestCase):
    def test_menu_and_screens_run_without_errors(self):
        """Drive `doctor i` in a pseudo-terminal through read-only screens (never a fix, never a sudo prompt)."""
        import fcntl, pty, re, select, struct, termios
        # Scripted keys must never reach a real password prompt: this sudo always refuses, without asking.
        fake = os.path.join(TMP, "no-sudo-bin")
        os.makedirs(fake, exist_ok=True)
        with open(os.path.join(fake, "sudo"), "w") as fh:
            fh.write("#!/bin/sh\nexit 1\n")
        os.chmod(os.path.join(fake, "sudo"), 0o755)
        pid, fd = pty.fork()
        if pid == 0:
            os.environ["PATH"] = fake + os.pathsep + os.environ["PATH"]
            os.execv(sys.executable, [sys.executable, "-I", str(Path(__file__).resolve().parent.parent / "bin/doctor"), "i", "--no-sudo"])
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 140, 0, 0))
        out = b""

        def drain(secs):
            nonlocal out
            end = time.time() + secs
            while time.time() < end:
                if select.select([fd], [], [], 0.2)[0]:
                    try:
                        out += os.read(fd, 65536)
                    except OSError:
                        return

        def send(keys, secs=1.5):
            os.write(fd, keys.encode())
            drain(secs)
        drain(4)
        send("\x1b[B")                              # arrow down, then a letter jumps
        send("t", 3); send("\r", 2); send("\r", 2)   # Top apps (live): open the first one's card, back to the list
        send("s", 3); send("\x1b", 2)               # sort by CPU, Esc back to the menu
        send("s", 5); send("/", 1); send("dbus\n", 4); send("\x1b", 1); send("\x1b", 2)  # Services: find, clear, back
        send("i", 4); send("\x1b[B", 1); send("\x1b", 2)   # This computer: move, then back
        for screen in "peukg":                      # Ports, Temperatures, Startup, App kills, Logs: move, then back
            send(screen, 6); send("\x1b[B", 1); send("\x1b", 2)
        send("r", 2); send("n", 2)                  # the rootkit scan asks first; n declines
        send("c", 15)                               # Check-up: scans, then the issue list
        for line in ["more", "1", "s", "b", "q", "memory", "disk", "pick", "history", "nope", "help"]:
            send(line + "\n", 2)
        send("ports\n", 4); send("\x1b", 2)          # screens open from the command line too
        send("m\n", 2)
        send("b", 2); send("\x1b", 2)               # Big files: the drive picker, Esc back
        send(":", 2); send("svc dbus\n", 3); send("m\n", 2)   # command line, a service, m from inside it
        send("\x18", 3)                             # Ctrl+X closes from the menu
        os.waitpid(pid, 0)
        text = re.sub(r"\x1b\[[\d;?]*[a-zA-Z]", "", out.decode(errors="replace"))
        self.assertIn("Look closer", text)                 # the main menu comes first, no scan before it
        self.assertLess(text.index("Look closer"), text.index("Needs attention") if "Needs attention" in text else 10**9)
        self.assertIn("Top apps  ·", text)
        self.assertIn("started by", text)                 # a process card
        self.assertIn("matching 'dbus'", text)
        for title in ("Ports  ·", "Temperatures  ·", "Startup  ·", "App kills  ·", "Logs  ·"):
            self.assertIn(title, text)
        self.assertIn("WHAT", text)                        # This computer's list
        self.assertIn("▸", text)                           # the selected row explains itself
        self.assertIn("Start it? y/N", text)
        self.assertIn("Check-up · limited", text)
        self.assertIn("[1/", text)
        self.assertGreaterEqual(text.count("[1/"), 2, "b went back to the first issue")
        self.assertIn("Unknown command 'nope'", text)
        self.assertIn("Where should I look?", text)
        self.assertIn("dbus.service", text)
        self.assertGreaterEqual(text.count("Look closer"), 10, "every screen came back to the main menu")
        self.assertIn("Closed (Ctrl+X)", text)
        self.assertNotIn("Traceback", text)


if __name__ == "__main__":
    unittest.main()
