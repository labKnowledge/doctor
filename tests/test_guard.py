"""Commit guard: the scanner, and the hooks in a throwaway repository and home (the real git config is never touched)."""
import os, subprocess, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from doctor import guard  # noqa: E402

# Built from pieces so this file never holds a whole fake secret (and doesn't trip the guard itself).
GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
AWS = "AKIA" + "Q3EGXYZ7RTUV2WAB"
PW = "Tr0ub4" + "dor&3xQ"


class Scanner(unittest.TestCase):
    def test_known_formats(self):
        self.assertEqual(guard.scan_line(f'token = "{GH}"')[0][:2], ("GitHub token", guard.SURE))
        self.assertEqual(guard.scan_line(f"aws={AWS}")[0][:2], ("AWS access key", guard.SURE))
        self.assertEqual(guard.scan_line("-----BEGIN RSA " + "PRIVATE KEY-----")[0][0], "private key")
        self.assertEqual(guard.scan_line("postgres://app:" + "S3cr3tPw0rd!@db:5432/x")[0][:2], ("password in a URL", guard.LIKELY))

    def test_generic_secret_is_likely(self):
        self.assertEqual(guard.scan_line(f'password = "{PW}"')[0][1], guard.LIKELY)

    def test_not_secrets(self):
        for line in ['key = "AKIA' + 'IOSFODNN7EXAMPLE"', 'password = os.environ["DB_PASSWORD"]', "apiKey: process.env.KEY,",
                     "token: accessToken,", "password: Optional[str] = None", 'api_key = "your-api-key-here"',
                     "token = get_token(user)", "postgres://user:password@localhost/db", f'password = "{PW}"  # doctor:allow']:
            self.assertEqual(guard.scan_line(line), [], line)

    def test_secret_files(self):
        self.assertEqual(guard.secret_file("app/.env"), ("environment file", guard.SURE))
        self.assertEqual(guard.secret_file("deploy/id_ed25519")[1], guard.SURE)
        for name in (".env.example", "id_rsa.pub", "README.md"):
            self.assertIsNone(guard.secret_file(name), name)

    def test_diff_lines_and_ignores(self):
        diff = ("diff --git a/x.py b/x.py\nnew file mode 100644\n--- /dev/null\n+++ b/x.py\n@@ -0,0 +1,2 @@\n"
                f"+print(1)\n+t = \"{GH}\"\n"
                "diff --git a/.env b/.env\nnew file mode 100644\n--- /dev/null\n+++ b/.env\n@@ -0,0 +1 @@\n+A=1\n")
        found = guard.scan_diff(diff)
        self.assertEqual([(f["path"], f["line"]) for f in found], [("x.py", 2), (".env", None)])
        self.assertNotIn(GH, str(found), "secrets are never shown in full")
        self.assertEqual(guard.scan_diff(diff, ignore=["x.py", ".env"]), [])

    def test_levels(self):
        sure, likely = {"certainty": guard.SURE}, {"certainty": guard.LIKELY}
        self.assertEqual([guard.blocks(sure, lv) for lv in guard.LEVELS], [False, True, True])
        self.assertEqual([guard.blocks(likely, lv) for lv in guard.LEVELS], [False, False, True])


class Hooks(unittest.TestCase):
    """The real thing: doctor guard on, commits, --no-verify, off, in a throwaway home with an earlier hooks folder."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="doctor-guard-")
        home = os.path.join(self.tmp, "home")
        self.prev = os.path.join(home, "prevhooks")
        os.makedirs(self.prev)
        self.env = {**os.environ, "HOME": home, "XDG_DATA_HOME": os.path.join(home, "share"),
                    "XDG_CONFIG_HOME": os.path.join(home, "config"), "DOCTOR_DATA": os.path.join(self.tmp, "state"),
                    "GIT_CONFIG_NOSYSTEM": "1", "DISPLAY": "", "WAYLAND_DISPLAY": ""}
        self.env.pop("DOCTOR_GUARD", None)
        with open(os.path.join(self.prev, "pre-commit"), "w") as fh:   # looks the repo's hook up the loop-prone way
            fh.write('#!/bin/sh\necho PREV\nh="$(git rev-parse --git-path hooks/pre-commit)"; [ -x "$h" ] && exec "$h"\nexit 0\n')
        os.chmod(os.path.join(self.prev, "pre-commit"), 0o755)
        self.repo = os.path.join(self.tmp, "repo")
        os.makedirs(self.repo)
        for args in (["config", "--global", "user.name", "t"], ["config", "--global", "user.email", "t@t"],
                     ["config", "--global", "core.hooksPath", self.prev], ["init", "-q"]):
            self.git(*args)
        with open(os.path.join(self.repo, ".git/hooks/pre-commit"), "w") as fh:
            fh.write("#!/bin/sh\necho REPO\n")
        os.chmod(os.path.join(self.repo, ".git/hooks/pre-commit"), 0o755)

    def git(self, *args, env=None):
        return subprocess.run(["git", *args], cwd=self.repo, env={**self.env, **(env or {})}, capture_output=True,
                              text=True, timeout=30, stdin=subprocess.DEVNULL, start_new_session=True)

    def doctor(self, *args):
        return subprocess.run([sys.executable, "-I", str(ROOT / "bin/doctor"), "guard", *args], cwd=self.repo, env=self.env,
                              capture_output=True, text=True, timeout=60)

    def commit(self, name, text, *flags, env=None):
        with open(os.path.join(self.repo, name), "w") as fh:
            fh.write(text + "\n")
        self.git("add", name)
        return self.git("commit", "-qm", name, *flags, env=env)

    def count(self):
        return len(self.git("log", "--oneline").stdout.splitlines())

    def test_guard_end_to_end(self):
        self.assertIn("Commit guard on", self.doctor("on").stdout)
        p = self.commit("a.txt", "hello")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("PREV", p.stdout + p.stderr, "the earlier hooks folder still runs")
        self.assertIn("REPO", p.stdout + p.stderr, "and the repository's own hook, without looping")

        p = self.commit("cfg.py", f't = "{GH}"')
        self.assertEqual(p.returncode, 1)
        self.assertIn("GitHub token", p.stderr)
        self.assertIn("DOCTOR_GUARD=allow", p.stderr, "no terminal: says how to go ahead")
        self.assertEqual(self.count(), 1)

        p = self.git("commit", "-qm", "anyway", env={"DOCTOR_GUARD": "allow"})
        self.assertEqual(p.returncode, 0, p.stderr)
        p = self.commit("b.py", f"k = '{AWS}'", "--no-verify")
        self.assertIn("pre-commit check was skipped", p.stderr, "post-commit still tells")
        self.assertEqual(self.count(), 3)
        hows = {r["path"]: r["how"] for r in guard_exposures(self.env)}
        self.assertEqual(hows, {"cfg.py": "allowed", "b.py": "bypassed"})

        self.doctor("relaxed", "--here")
        p = self.commit("c.py", f'password = "{PW}"')
        self.assertEqual(p.returncode, 0, "relaxed only warns")
        self.assertIn("warning only", p.stderr)

        self.assertIn("uses", self.doctor("off").stdout)
        self.assertEqual(self.git("config", "--global", "--get", "core.hooksPath").stdout.strip(), self.prev)


def guard_exposures(env):
    old = os.environ.get("DOCTOR_DATA")
    os.environ["DOCTOR_DATA"] = env["DOCTOR_DATA"]
    try:
        return guard.exposures()
    finally:
        if old is None:
            os.environ.pop("DOCTOR_DATA")
        else:
            os.environ["DOCTOR_DATA"] = old


if __name__ == "__main__":
    unittest.main()
