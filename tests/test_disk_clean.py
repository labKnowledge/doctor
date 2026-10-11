"""Run: python3 -m unittest discover -s tests   (no dependencies; uses throwaway folders only)."""
import os, shutil, sys, tempfile, time, unittest
from pathlib import Path

TMP = tempfile.mkdtemp(prefix="disk-clean-test-")
os.environ["DISK_CLEAN_DATA"] = os.path.join(TMP, "state")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from disk_clean import DiskCleanError, parse_picks, remove, scan  # noqa: E402
from disk_clean.scan import held_paths, in_use  # noqa: E402

OLD = time.time() - 90 * 86400


def make_project(root, name, idle, artifact="node_modules", marker="package.json", mb=60):
    proj = Path(root) / name
    (proj / "src").mkdir(parents=True)
    (proj / marker).write_text("{}")
    (proj / "src" / "a.js").write_text("x")
    (proj / artifact).mkdir()
    with open(proj / artifact / "blob", "wb") as f:
        f.write(os.urandom(mb << 20))
    if idle:
        for p in (proj / marker, proj / "src" / "a.js", proj / "src", proj):
            os.utime(p, (OLD, OLD))
    return proj


class DiskCleanTest(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(dir=TMP)

    def test_lists_only_idle_projects_and_removes_only_the_artifact(self):
        old = make_project(self.root, "old", idle=True)
        make_project(self.root, "fresh", idle=False)
        r = scan(self.root)
        self.assertEqual([i["label"] for i in r["items"]], ["old: node_modules"])
        res = remove("1")
        self.assertEqual(res["results"][0]["status"], "removed")
        self.assertFalse((old / "node_modules").exists())
        self.assertTrue((old / "src" / "a.js").exists())
        self.assertEqual(remove("1")["results"][0]["status"], "already removed")

    def test_remove_by_id(self):
        make_project(self.root, "old", idle=True)
        item = scan(self.root)["items"][0]
        self.assertEqual(remove(None, ids=[item["id"]])["results"][0]["status"], "removed")

    def test_hidden_folders_are_not_projects(self):
        make_project(Path(self.root) / ".vscode-server" / "extensions", "ext", idle=True, artifact="dist")
        self.assertEqual(scan(self.root)["items"], [])

    def test_in_use_items_are_skipped(self):
        old = make_project(self.root, "old", idle=True)
        with open(old / "node_modules" / "blob", "rb"):
            self.assertEqual(scan(self.root)["items"], [])

    def test_swap_files_are_protected(self):
        try:
            swaps = [l.split()[0] for l in Path("/proc/swaps").read_text().splitlines()[1:]]
        except OSError:
            self.skipTest("no /proc/swaps")
        held = held_paths()
        for s in swaps:
            self.assertTrue(in_use([s], held), s)

    def test_parse_picks(self):
        self.assertEqual(parse_picks("1 3 5-7", 10), [1, 3, 5, 6, 7])
        self.assertEqual(parse_picks("2,4", 10), [2, 4])
        self.assertEqual(parse_picks("all", 3), [1, 2, 3])
        self.assertEqual(parse_picks([1, 2], 3), [1, 2])
        for bad in ("x", "11", ""):
            with self.assertRaises(DiskCleanError):
                parse_picks(bad, 10)


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
