"""Run: python3 -m unittest discover -s tests   (no dependencies; read-only on the system, writes only to a temp folder)."""
import io, json, os, sys, tempfile, time, unittest
from contextlib import redirect_stdout
from pathlib import Path

TMP = tempfile.mkdtemp(prefix="doctor-test-")
os.environ["DOCTOR_DATA"] = TMP
os.environ["DOCTOR_NO_AGENT"] = "1"  # tests never call the assistant
os.environ["DISK_CLEAN_DATA"] = os.path.join(TMP, "disk-clean")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from doctor import CHECKS, Ctx, run_checks  # noqa: E402
from doctor.cli import main, parse_numbers, render  # noqa: E402
from doctor.core import AREAS, RANK, finding, fix, normalize  # noqa: E402
from doctor.health import app_name  # noqa: E402


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
        pid, fd = pty.fork()
        if pid == 0:
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
        send("s", 4); send("/dbus\n", 4); send("\n")  # Services: search, then back
        send("c", 15)                               # Check-up: scans, then the issue list
        for line in ["more", "1", "s", "b", "q", "ports", "kills", "temps", "memory", "boot", "logs", "disk", "pick",
                     "history", "nope", "help", "m"]:
            send(line + "\n", 2)
        send("b", 2); send("\x1b", 2)               # Big files: the drive picker, Esc back
        send(":", 2); send("svc dbus\n", 3); send("m\n", 2)   # command line, a service, m from inside it
        send("\x18", 3)                             # Ctrl+X closes from the menu
        os.waitpid(pid, 0)
        text = re.sub(r"\x1b\[[\d;?]*[a-zA-Z]", "", out.decode(errors="replace"))
        self.assertIn("Look closer", text)                 # the main menu comes first, no scan before it
        self.assertLess(text.index("Look closer"), text.index("Needs attention") if "Needs attention" in text else 10**9)
        self.assertIn("Top apps · by memory", text)
        self.assertIn("started by", text)                 # a process card
        self.assertIn("Top apps · by CPU", text)
        self.assertIn("Matching 'dbus'", text)
        self.assertIn("Check-up · limited", text)
        self.assertIn("[1/", text)
        self.assertGreaterEqual(text.count("[1/"), 2, "b went back to the first issue")
        self.assertIn("Unknown command 'nope'", text)
        self.assertIn("Where should I look?", text)
        self.assertIn("dbus.service", text)
        self.assertGreaterEqual(text.count("Look closer"), 5, "every screen came back to the main menu")
        self.assertIn("Closed (Ctrl+X)", text)
        self.assertNotIn("Traceback", text)


if __name__ == "__main__":
    unittest.main()
