"""Run: python3 -m unittest discover -s tests   (no dependencies; read-only on the system, writes only to a temp folder)."""
import io, json, os, sys, tempfile, time, unittest
from contextlib import redirect_stdout
from pathlib import Path

TMP = tempfile.mkdtemp(prefix="system-check-test-")
os.environ["SYSTEM_CHECK_DATA"] = TMP
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from system_check import CHECKS, Ctx, run_checks  # noqa: E402
from system_check.cli import main, parse_numbers, render  # noqa: E402
from system_check.core import AREAS, RANK, finding, fix, normalize  # noqa: E402
from system_check.health import app_name  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
