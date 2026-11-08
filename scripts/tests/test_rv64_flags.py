import copy
import json
import tempfile
import unittest
from pathlib import Path

from scripts.repo.source_conformance_lib import rv64_flags as F
from scripts.repo.check_source_conformance import main


class Rv64FlagsTests(unittest.TestCase):
    def test_shipped_ci_enforces_declarations_and_strict_promotion(self):
        from scripts.ci import FAST_PLAN
        self.assertTrue(any("scripts/repo/check_source_conformance.py" in command for command in FAST_PLAN))
        root = Path(__file__).resolve().parents[2]
        strict = (root / "build_support/gates/release.zig").read_text().split("const strict =", 1)[1]
        self.assertIn('"scripts/repo/check_source_conformance.py", "--strict-rv64-flags"', strict)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        self.name = "STWO_RV64_" + "DECLARED"
        self.source = self.repo / "src/owner.zig"
        self.source.parent.mkdir()
        self.expression = f'const x = std.posix.getenv("{self.name}") orelse "0";'
        self.source.write_text(self.expression)
        self.payload = {"schema": "rv64-flag-registry/v1", "flags": {self.name: {
            "owner": "src/owner.zig", "default": "0", "status": "runtime",
            "date": "2026-01-01", "references": ["src/owner.zig"],
            "default_evidence": {"path": "src/owner.zig", "text": self.expression},
        }}}
        self.save()

    def save(self):
        path = self.repo / F.REGISTRY
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(self.payload))

    def test_current_declaration_and_source_default_are_required(self):
        self.assertEqual([], F.check(self.repo))
        self.source.write_text(self.expression.replace('"0"', '"1"'))
        self.assertTrue(any("source expression changed" in e for e in F.check(self.repo)))

    def test_undeclared_flag_cannot_be_generated_or_baselined(self):
        self.source.write_text(self.expression + '\nconst y = "' + "STWO_RV64_" + 'NEW";')
        before = (self.repo / F.REGISTRY).read_bytes()
        self.assertTrue(any("undeclared" in e for e in F.check(self.repo, refresh=True)))
        self.assertEqual(before, (self.repo / F.REGISTRY).read_bytes())
        self.assertEqual(1, main(["--repo", str(self.repo), "--update-baseline"]))
        self.assertFalse((self.repo / "conformance/source-baseline.json").exists())

    def test_refresh_changes_only_references_and_requires_reviewed_metadata(self):
        (self.repo / "scripts").mkdir()
        (self.repo / "scripts/caller.py").write_text(f'name = "{self.name}"')
        before = copy.deepcopy(self.payload["flags"][self.name])
        self.assertTrue(any("stale generated" in e for e in F.check(self.repo)))
        self.assertEqual([], F.check(self.repo, refresh=True))
        after = F.load(self.repo)["flags"][self.name]
        self.assertEqual(["scripts/caller.py", "src/owner.zig"], after.pop("references"))
        before.pop("references")
        self.assertEqual(before, after)

    def test_missing_owner_date_default_status_and_stale_entries_fail(self):
        original = copy.deepcopy(self.payload)
        for key, value in (("owner", "../outside"), ("date", "bad"), ("default", ""),
                           ("status", "anything"), ("default_evidence", None)):
            with self.subTest(key=key):
                self.payload = copy.deepcopy(original)
                self.payload["flags"][self.name][key] = value
                self.save()
                self.assertTrue(F.check(self.repo))
        self.source.write_text("")
        self.assertTrue(any("stale RV64" in e for e in F.check(self.repo)))

    def test_missing_and_duplicate_registry_fail(self):
        path = self.repo / F.REGISTRY
        path.unlink()
        self.assertTrue(F.check(self.repo))
        path.write_text('{"schema":"rv64-flag-registry/v1","flags":{},"flags":{}}')
        self.assertTrue(any("duplicate" in e for e in F.check(self.repo)))

    def test_reader_cannot_be_relabelled_to_hide_from_live_count(self):
        for status in ("constant", "reference-only"):
            self.payload["flags"][self.name]["status"] = status
            self.save()
            self.assertTrue(any("live count" in e for e in F.check(self.repo)))

    def test_native_cuda_shell_and_active_presets_are_scanned_caches_are_not(self):
        for relative in ("src/native/a.cu", "scripts/run.sh", ".github/workflows/gpu.yml",
                         "conformance/rv64/presets/integration-stack-preset.json"):
            path = self.repo / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('"' + "STWO_RV64_" + 'NEW"')
            self.assertTrue(any("undeclared" in e for e in F.check(self.repo)), relative)
            path.unlink()
        cache = self.repo / "src/.zig-cache/old.zig"
        cache.parent.mkdir()
        cache.write_text('"' + "STWO_RV64_" + 'OLD"')
        self.assertEqual([], F.check(self.repo))

    def test_dynamic_per_device_budget_family_has_one_explicit_declaration(self):
        self.source.write_text('const x = "' + F.DEVICE_BUDGET_PREFIX + '{}";')
        self.assertEqual({F.DEVICE_BUDGET_FAMILY: ["src/owner.zig"]}, F.references(self.repo))
        self.source.write_text('const x = "' + F.DEVICE_BUDGET_PREFIX + '17";')
        self.assertEqual({F.DEVICE_BUDGET_FAMILY: ["src/owner.zig"]}, F.references(self.repo))

    def test_strict_promotion_target_is_not_grandfathered(self):
        self.name = "STWO_RV64_" + "M8_PENDING"
        self.source.write_text(f'const x = "{self.name}";')
        self.payload["flags"] = {self.name: {"owner": "src/owner.zig", "default": "off",
            "status": "runtime", "date": "2026-01-01", "references": ["src/owner.zig"],
            "default_evidence": {"path": "src/owner.zig", "text": self.source.read_text()}}}
        self.save()
        self.assertEqual([], F.check(self.repo))
        self.assertTrue(any("promotion or removal" in e for e in F.check(self.repo, strict=True)))
        entry = self.payload["flags"][self.name]
        self.payload["flags"] = {"STWO_RV64_" + f"LIVE_{i}": copy.deepcopy(entry) for i in range(60)}
        self.source.write_text(" ".join(self.payload["flags"]))
        self.save()
        self.assertTrue(any("required <60" in e for e in F.check(self.repo, strict=True)))
