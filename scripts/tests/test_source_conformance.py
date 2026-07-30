import json
import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from scripts.check_source_conformance import (
    BASELINE_TRACKS,
    BASELINE_VERSION,
    DEFAULT_BASELINE_TRACK,
    ROOT_ALLOWLIST,
    Finding,
    inventory,
    load_baseline,
    main,
    measure,
    scan,
    write_baseline,
)
from scripts.source_conformance_lib.policy import ACTIVE_FORMAL_EVIDENCE_ROOTS
from scripts.source_conformance_lib import comments, policy
from scripts.source_conformance_lib.model import is_headroom


class SourceConformanceTests(unittest.TestCase):
    def test_root_build_ceiling_matches_formal_dispatcher_contract(self) -> None:
        self.assertEqual(200, policy.BUILD_ROOT_CEILING)
        self.assertLess(policy.BUILD_ROOT_CEILING, policy.BUILD_SUPPORT_CEILING)

    @staticmethod
    def baseline_entry(key: str, **overrides: object) -> dict[str, object]:
        entry: dict[str, object] = {
            "key": key,
            "owner": "test-owner",
            "track": DEFAULT_BASELINE_TRACK,
            "reason": "legacy test debt",
            "plan": "plan.md",
            "next_extraction": "Extract the test responsibility.",
        }
        entry.update(overrides)
        return entry

    def test_detects_dependency_size_and_root_violations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / "src/core").mkdir(parents=True)
            (repo / "src/backends/metal").mkdir(parents=True)
            (repo / "src/tool_cli.zig").write_text("pub fn main() void {}\n", encoding="utf-8")
            (repo / "src/core/bad.zig").write_text(
                'const metal = @import("../backends/metal/mod.zig");\n' + "\n" * 850,
                encoding="utf-8",
            )
            (repo / "src/backends/metal/mod.zig").write_text("", encoding="utf-8")
            keys = {finding.key for finding in scan(repo)}
            self.assertIn("root-source:tool_cli.zig", keys)
            self.assertIn("file-size:core/bad.zig", keys)
            self.assertIn("dependency:core/bad.zig->backends/metal/mod.zig", keys)

    def test_generated_file_requires_generator_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / "src/core").mkdir(parents=True)
            (repo / "src/core/generated.zig").write_text(
                "// Generated file. Generator: tools/example.zig\n"
                "// Regenerate: zig build generate-example\n"
                + "\n" * 900,
                encoding="utf-8",
            )
            self.assertEqual([], scan(repo))

            (repo / "src/core/generated.zig").write_text(
                "// Generated file. Generator: tools/example.zig\n" + "\n" * 900,
                encoding="utf-8",
            )
            self.assertIn("file-size:core/generated.zig", {finding.key for finding in scan(repo)})

    def test_inventories_owned_source_outside_src_and_excludes_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            sources = {
                "build.zig": "build",
                "build_support/options.py": "build",
                "scripts/report.py": "python",
                "tools/oracle/src/main.rs": "rust-tool",
            }
            for relative, _ in sources.items():
                path = repo / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("\n" * 851, encoding="utf-8")

            excluded = (
                "scripts/__pycache__/cached.py",
                "scripts/generated/schema.py",
                "scripts/vendor/library.py",
                "tools/oracle/target/debug/build.rs",
                "tools/oracle/vendor/dependency.rs",
                "ethereum-guest/src/main.rs",
            )
            for relative in excluded:
                path = repo / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("\n" * 851, encoding="utf-8")

            owned = {source.display_path.as_posix(): source.category for source in inventory(repo)}
            self.assertEqual(sources, owned)
            keys = {finding.key for finding in scan(repo)}
            self.assertEqual(
                {f"file-size:{relative}" for relative in sources}
                | {"thin-owner:build.zig", "thin-owner:build_support/options.py"},
                keys,
            )

    def test_dependency_enforcement_is_limited_to_src(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / "src/core").mkdir(parents=True)
            (repo / "src/backends/metal").mkdir(parents=True)
            (repo / "src/backends/metal/mod.zig").write_text("", encoding="utf-8")
            (repo / "build.zig").write_text(
                'const metal = @import("src/backends/metal/mod.zig");\n',
                encoding="utf-8",
            )
            (repo / "src/core/bad.zig").write_text(
                'const metal = @import("../backends/metal/mod.zig");\n',
                encoding="utf-8",
            )
            dependencies = {
                finding.key for finding in scan(repo) if finding.key.startswith("dependency:")
            }
            self.assertEqual(
                {"dependency:core/bad.zig->backends/metal/mod.zig"},
                dependencies,
            )

    def test_objective_c_manual_source_uses_the_same_size_ceiling(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / "src/backends/metal").mkdir(parents=True)
            (repo / "src/backends/metal/runtime.m").write_text("\n" * 851, encoding="utf-8")
            self.assertIn(
                "file-size:backends/metal/runtime.m",
                {finding.key for finding in scan(repo)},
            )

    def test_metal_size_and_repository_include_rules_are_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            shader_root = repo / "src/backends/metal/shaders"
            include_root = shader_root / "include"
            include_root.mkdir(parents=True)
            (include_root / "m31.metal").write_text("inline uint m31_add(uint a, uint b);\n", encoding="utf-8")
            (shader_root / "valid.metal").write_text(
                '#include <metal_stdlib>\n#include "stwo_zig/m31.metal"\n',
                encoding="utf-8",
            )
            (shader_root / "oversized.metal").write_text("\n" * 851, encoding="utf-8")
            (shader_root / "escape.metal").write_text(
                '#include "../../outside.metal"\n',
                encoding="utf-8",
            )
            keys = {finding.key for finding in scan(repo)}
            self.assertIn("file-size:backends/metal/shaders/oversized.metal", keys)
            self.assertIn(
                "shader-include:backends/metal/shaders/escape.metal->../../outside.metal",
                keys,
            )
            self.assertNotIn(
                "shader-include:backends/metal/shaders/valid.metal->stwo_zig/m31.metal",
                keys,
            )

    def test_deliberate_module_roots_are_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / "src").mkdir()
            for name in ROOT_ALLOWLIST:
                (repo / "src" / name).write_text("pub const marker = true;\n", encoding="utf-8")
            self.assertEqual([], scan(repo))

    def test_python_dependencies_respect_command_library_and_deferred_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            files = {
                "scripts/active_command.py": "VALUE = 1\n",
                "scripts/active_runner.py": "import active_command\n",
                "scripts/sn_pie_worker.py": "VALUE = 2\n",
                "scripts/consumer.py": "import sn_pie_worker\n",
                "scripts/feature_lib/__init__.py": "from .model import VALUE\n",
                "scripts/feature_lib/model.py": "from active_command import VALUE\n",
                "scripts/native_proof_matrix_lib/model.py": "VALUE = 3\n",
                "scripts/native_profile_capture_lib/evidence.py": (
                    "from native_proof_matrix_lib.model import VALUE\n"
                ),
                "scripts/metal_profile_report_lib/__init__.py": "VALUE = 4\n",
                "scripts/native_profile_capture_lib/contract.py": (
                    "from metal_profile_report_lib import VALUE\n"
                ),
                "scripts/tests/test_consumer.py": "import active_command\n",
            }
            for relative, text in files.items():
                path = repo / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")

            keys = {finding.key for finding in scan(repo)}
            self.assertIn(
                "python-dependency:scripts/consumer.py->scripts/sn_pie_worker.py",
                keys,
            )
            self.assertIn(
                "python-dependency:scripts/feature_lib/model.py->scripts/active_command.py",
                keys,
            )
            self.assertNotIn(
                "python-dependency:scripts/tests/test_consumer.py->scripts/active_command.py",
                keys,
            )
            self.assertNotIn(
                "python-dependency:scripts/active_runner.py->scripts/active_command.py",
                keys,
            )
            self.assertNotIn(
                "python-dependency:scripts/feature_lib/__init__.py->scripts/feature_lib/model.py",
                keys,
            )
            self.assertNotIn(
                "python-dependency:scripts/native_profile_capture_lib/evidence.py"
                "->scripts/native_proof_matrix_lib/model.py",
                keys,
            )
            self.assertNotIn(
                "python-dependency:scripts/native_profile_capture_lib/contract.py"
                "->scripts/metal_profile_report_lib/__init__.py",
                keys,
            )

    def test_build_graph_rejects_non_support_imports_cycles_and_missing_static_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / "build_support").mkdir(parents=True)
            (repo / "src").mkdir()
            (repo / "src/core.zig").write_text("", encoding="utf-8")
            (repo / "build.zig").write_text(
                'const helper = @import("build_support/helper.zig");\n'
                'const core = @import("src/core.zig");\n'
                'pub fn build(b: anytype) void { _ = b.path("src/missing.zig"); }\n',
                encoding="utf-8",
            )
            (repo / "build_support/helper.zig").write_text(
                'const other = @import("other.zig");\n',
                encoding="utf-8",
            )
            (repo / "build_support/other.zig").write_text(
                'const helper = @import("helper.zig");\n',
                encoding="utf-8",
            )

            keys = {finding.key for finding in scan(repo)}
            self.assertIn("build-dependency:build.zig->src/core.zig", keys)
            self.assertIn("build-path:build.zig->src/missing.zig", keys)
            self.assertIn("build-cycle:build_support/helper.zig", keys)
            self.assertIn("build-cycle:build_support/other.zig", keys)

    def test_comments_describe_edges_without_declaring_them(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / "build_support").mkdir(parents=True)
            (repo / "src/core").mkdir(parents=True)
            (repo / "src/backends/metal").mkdir(parents=True)
            (repo / "src/backends/metal/mod.zig").write_text("", encoding="utf-8")
            (repo / "build_support/helper.zig").write_text("pub const marker = true;\n", encoding="utf-8")
            (repo / "build.zig").write_text(
                '/// Zig resolves `@import("src/core.zig")` against the importing file,\n'
                '/// and `b.path("src/missing.zig")` against the build root.\n'
                'const helper = @import("build_support/helper.zig");\n',
                encoding="utf-8",
            )
            (repo / "src/core/documented.zig").write_text(
                '//! Compare with `@import("../backends/metal/mod.zig")`, which this\n'
                "//! layer must never do.\n"
                "pub const marker = true;\n",
                encoding="utf-8",
            )
            self.assertEqual([], scan(repo))

            (repo / "build.zig").write_text(
                'const core = @import("src/core.zig");\n'
                'pub fn build(b: anytype) void { _ = b.path("src/missing.zig"); }\n',
                encoding="utf-8",
            )
            (repo / "src/core/documented.zig").write_text(
                'const metal = @import("../backends/metal/mod.zig");\n',
                encoding="utf-8",
            )
            keys = {finding.key for finding in scan(repo)}
            self.assertIn("build-dependency:build.zig->src/core.zig", keys)
            self.assertIn("build-path:build.zig->src/missing.zig", keys)
            self.assertIn("dependency:core/documented.zig->backends/metal/mod.zig", keys)

    def test_double_slash_inside_a_string_literal_opens_no_comment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / "src").mkdir(parents=True)
            (repo / "src/core.zig").write_text("", encoding="utf-8")
            (repo / "build.zig").write_text(
                'const doc = "https://example.com/build.zig"; '
                'const core = @import("src/core.zig");\n'
                'pub fn build(b: anytype) void { const host = "https://example.com"; '
                '_ = host; _ = b.path("src/missing.zig"); }\n',
                encoding="utf-8",
            )
            keys = {finding.key for finding in scan(repo)}
            self.assertIn("build-dependency:build.zig->src/core.zig", keys)
            self.assertIn("build-path:build.zig->src/missing.zig", keys)

    def test_comment_blanking_preserves_offsets_and_metal_includes(self) -> None:
        source = 'const url = "https://example.com"; // @import("a.zig")\n'
        self.assertEqual(
            'const url = "https://example.com";' + " " * 20 + "\n",
            comments.strip_zig(source),
        )
        block = '/* #include "hidden.metal"\n*/\n#include "stwo_zig/m31.metal"\n'
        self.assertEqual(
            " " * 26 + "\n" + " " * 2 + '\n#include "stwo_zig/m31.metal"\n',
            comments.strip_c(block),
        )
        for text in (source, block, '\\\\ // multiline @import("b.zig")\n'):
            with self.subTest(text=text):
                self.assertEqual(
                    len(text.splitlines()),
                    len(comments.strip_zig(text).splitlines()),
                )

    def test_zig_entrypoint_measurement_ignores_braces_inside_comments(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            zig_root = repo / "src/bench/sample.zig"
            zig_root.parent.mkdir(parents=True)
            zig_root.write_text(
                "pub fn main() void {\n"
                '    // A closing } and a "{" inside prose end nothing.\n'
                + "    _ = 1;\n" * 199
                + "}\n",
                encoding="utf-8",
            )
            self.assertIn("thin-owner:bench/sample.zig", {finding.key for finding in scan(repo)})

    def test_native_rust_edges_reject_cross_tool_paths_missing_modules_and_cycles(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            crate = repo / "tools/stwo-interop-rs"
            (crate / "src").mkdir(parents=True)
            (repo / "tools/peer").mkdir(parents=True)
            (crate / "Cargo.toml").write_text(
                "[package]\nname = \"oracle\"\nversion = \"0.1.0\"\n"
                "[dependencies]\npeer = { path = \"../peer\" }\n",
                encoding="utf-8",
            )
            (crate / "src/main.rs").write_text(
                "mod alpha;\nmod beta;\nmod missing;\nfn main() {}\n",
                encoding="utf-8",
            )
            (crate / "src/alpha.rs").write_text(
                "mod child;\nuse crate::beta::Value;\n",
                encoding="utf-8",
            )
            (crate / "src/alpha").mkdir()
            (crate / "src/alpha/child.rs").write_text("pub struct Value;\n", encoding="utf-8")
            (crate / "src/beta.rs").write_text("use crate::alpha::Value;\n", encoding="utf-8")

            keys = {finding.key for finding in scan(repo)}
            self.assertIn("cargo-dependency:tools/stwo-interop-rs->tools/peer", keys)
            self.assertIn(
                "rust-module:tools/stwo-interop-rs/src/main.rs->missing",
                keys,
            )
            self.assertIn("rust-cycle:tools/stwo-interop-rs/src/alpha", keys)
            self.assertIn("rust-cycle:tools/stwo-interop-rs/src/beta", keys)
            self.assertNotIn(
                "rust-module:tools/stwo-interop-rs/src/alpha.rs->child",
                keys,
            )

    def test_thin_owner_caps_cover_active_performance_and_build_support_entrypoints(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            controller = repo / "scripts/benchmark_delta.py"
            controller.parent.mkdir(parents=True)
            controller.write_text("def main():\n" + "    pass\n" * 300, encoding="utf-8")
            zig_root = repo / "src/bench/sample.zig"
            zig_root.parent.mkdir(parents=True)
            zig_root.write_text(
                "pub fn main() void {\n" + "    _ = 1;\n" * 199 + "}\n",
                encoding="utf-8",
            )
            test_root = repo / "src/tests/native/mod.zig"
            test_root.parent.mkdir(parents=True)
            test_root.write_text("\n" * 301, encoding="utf-8")
            support = repo / "build_support/products.zig"
            support.parent.mkdir(parents=True)
            support.write_text("\n" * 501, encoding="utf-8")

            keys = {finding.key for finding in scan(repo)}
            self.assertIn("thin-owner:scripts/benchmark_delta.py", keys)
            self.assertIn("thin-owner:bench/sample.zig", keys)
            self.assertIn("thin-owner:tests/native/mod.zig", keys)
            self.assertIn("thin-owner:build_support/products.zig", keys)

    def test_size_ceilings_warn_at_ninety_percent_without_failing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            support = repo / "build_support/products.zig"
            support.parent.mkdir(parents=True)
            support.write_text("\n" * 449, encoding="utf-8")
            self.assertEqual([], [finding for finding in measure(repo) if is_headroom(finding)])

            support.write_text("\n" * 450, encoding="utf-8")
            notices = [finding for finding in measure(repo) if is_headroom(finding)]
            self.assertEqual(
                ["headroom:thin-owner:build_support/products.zig"],
                [notice.key for notice in notices],
            )
            self.assertIn(
                "build_support/products.zig: 450 lines approaches the 500-line "
                "build-support owner ceiling (50 line(s) of headroom)",
                notices[0].message,
            )
            self.assertEqual([], scan(repo))

            baseline = repo / "baseline.json"
            write_baseline(baseline, scan(repo))
            self.assertEqual({}, load_baseline(baseline))
            errors = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(errors):
                self.assertEqual(0, main(["--repo", str(repo), "--baseline", str(baseline)]))
            self.assertIn("warning: build_support/products.zig: 450 lines", errors.getvalue())
            self.assertNotIn("error:", errors.getvalue())

            support.write_text("\n" * 501, encoding="utf-8")
            errors = io.StringIO()
            with redirect_stderr(errors):
                self.assertEqual(1, main(["--repo", str(repo), "--baseline", str(baseline)]))
            self.assertIn(
                "error: build_support/products.zig: build-support owner exceeds the 500-line ceiling",
                errors.getvalue(),
            )

    def test_headroom_warnings_cover_manual_sources_and_python_entry_points(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            oversized = repo / "src/core/legacy.zig"
            oversized.parent.mkdir(parents=True)
            oversized.write_text("\n" * 765, encoding="utf-8")
            evidence_root = repo / "scripts/benchmark_delta.py"
            evidence_root.parent.mkdir(parents=True)
            evidence_root.write_text("def main():\n" + "    pass\n" * 89, encoding="utf-8")

            messages = {
                notice.key: notice.message
                for notice in measure(repo)
                if is_headroom(notice)
            }
            self.assertIn(
                "765 lines approaches the 850-line manual-source ceiling (85 line(s) of headroom)",
                messages["headroom:file-size:core/legacy.zig"],
            )
            self.assertIn(
                "90 lines approaches the 100-line entrypoint ceiling (10 line(s) of headroom)",
                messages["headroom:thin-owner:scripts/benchmark_delta.py"],
            )
            self.assertEqual([], scan(repo))

    def test_formal_evidence_root_registry_is_explicit_and_checked_in(self) -> None:
        expected = {
            "scripts/archive_native_matrix.py",
            "scripts/benchmark_delta.py",
            "scripts/benchmark_full.py",
            "scripts/benchmark_smoke.py",
            "scripts/architecture_host_gate.py",
            "scripts/build_architecture_receipt.py",
            "scripts/compare_optimization.py",
            "scripts/e2e_interop.py",
            "scripts/metal_core_aot_receipt.py",
            "scripts/metal_profile_report.py",
            "scripts/native_profile_capture.py",
            "scripts/native_proof_matrix.py",
            "scripts/profile_smoke.py",
            "scripts/check_riscv_release_contract.py",
            "scripts/riscv_release_evidence.py",
            "scripts/riscv_release_gate.py",
        }
        self.assertEqual(expected, set(ACTIVE_FORMAL_EVIDENCE_ROOTS))
        root = Path(__file__).resolve().parents[2]
        for relative in expected:
            with self.subTest(relative=relative):
                self.assertTrue((root / relative).is_file())

    def test_deep_controller_cap_and_stable_facade_are_mechanical(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            controller = repo / "scripts/example_lib/controller.py"
            controller.parent.mkdir(parents=True)
            controller.write_text("pass\n" * 851, encoding="utf-8")

            keys = {finding.key for finding in scan(repo)}
            self.assertIn("deep-controller:scripts/example_lib/controller.py", keys)

            controller.write_text("pass\n" * 850, encoding="utf-8")
            (repo / "scripts/example.py").write_text(
                "from example_lib.controller import main\n",
                encoding="utf-8",
            )
            keys = {finding.key for finding in scan(repo)}
            self.assertNotIn("deep-controller:scripts/example_lib/controller.py", keys)

    def test_baseline_round_trip_requires_explanations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "baseline.json"
            write_baseline(path, [Finding("file-size:a.zig", "too large", 900)])
            loaded = load_baseline(path)
            self.assertIn("file-size:a.zig", loaded)
            self.assertEqual("source-conformance", loaded["file-size:a.zig"]["owner"])
            self.assertEqual(DEFAULT_BASELINE_TRACK, loaded["file-size:a.zig"]["track"])
            self.assertIn("next_extraction", loaded["file-size:a.zig"])
            path.write_text(json.dumps({
                "version": BASELINE_VERSION,
                "findings": [
                    self.baseline_entry("file-size:a.zig"),
                ],
            }), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_baseline(path)
            path.write_text(
                json.dumps({"version": BASELINE_VERSION, "findings": [{"key": "bad"}]}),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_baseline(path)
            path.write_text(json.dumps({
                "version": BASELINE_VERSION,
                "findings": [
                    self.baseline_entry("duplicate"),
                    self.baseline_entry("duplicate"),
                ],
            }), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_baseline(path)

    def test_baseline_requires_owner_next_extraction_and_applicable_cap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "baseline.json"
            invalid_entries = (
                self.baseline_entry("dependency:a->b", owner="Team Name"),
                self.baseline_entry("dependency:a->b", track="unclassified"),
                self.baseline_entry("dependency:a->b", track=None),
                self.baseline_entry("dependency:a->b", next_extraction=""),
                self.baseline_entry("dependency:a->b", max_lines=900),
            )
            for entry in invalid_entries:
                path.write_text(
                    json.dumps({"version": BASELINE_VERSION, "findings": [entry]}),
                    encoding="utf-8",
                )
                with self.assertRaises(ValueError):
                    load_baseline(path)

    def test_checked_in_schema_matches_enforced_baseline_contract(self) -> None:
        repo = Path(__file__).resolve().parents[2]
        schema = json.loads(
            (repo / "conformance/source-baseline.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(BASELINE_VERSION, schema["properties"]["version"]["const"])
        finding = schema["$defs"]["finding"]
        self.assertEqual(
            {"key", "owner", "track", "reason", "next_extraction", "plan"},
            set(finding["required"]),
        )
        self.assertEqual(
            list(BASELINE_TRACKS),
            finding["properties"]["track"]["enum"],
        )
        self.assertEqual(850, finding["properties"]["max_lines"]["exclusiveMinimum"])
        self.assertFalse(finding["additionalProperties"])

    def test_update_accepts_baseline_outside_repo(self) -> None:
        with tempfile.TemporaryDirectory() as repo_temporary, tempfile.TemporaryDirectory() as output_temporary:
            repo = Path(repo_temporary)
            (repo / "src").mkdir()
            baseline = Path(output_temporary) / "baseline.json"
            output = io.StringIO()
            with redirect_stdout(output):
                result = main([
                    "--repo",
                    str(repo),
                    "--baseline",
                    str(baseline),
                    "--update-baseline",
                ])
            self.assertEqual(0, result)
            self.assertTrue(baseline.exists())
            self.assertIn(str(baseline), output.getvalue())

    def test_ratchet_rejects_new_and_stale_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            (repo / "src").mkdir()
            plan = repo / "conformance/decomposition-plan.md"
            plan.parent.mkdir(parents=True)
            plan.write_text("# Plan\n", encoding="utf-8")
            source = repo / "src/tool.zig"
            source.write_text("pub fn main() void {}\n", encoding="utf-8")
            baseline = repo / "baseline.json"
            write_baseline(baseline, [])
            with redirect_stderr(io.StringIO()):
                self.assertEqual(1, main(["--repo", str(repo), "--baseline", str(baseline)]))

            write_baseline(baseline, scan(repo))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(0, main(["--repo", str(repo), "--baseline", str(baseline)]))

            source.unlink()
            with redirect_stderr(io.StringIO()):
                self.assertEqual(1, main(["--repo", str(repo), "--baseline", str(baseline)]))

    def test_ratchet_rejects_oversized_file_growth_and_missing_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            source = repo / "src/core/legacy.zig"
            source.parent.mkdir(parents=True)
            source.write_text("\n" * 900, encoding="utf-8")
            baseline = repo / "baseline.json"
            write_baseline(baseline, scan(repo))

            with redirect_stderr(io.StringIO()):
                self.assertEqual(1, main(["--repo", str(repo), "--baseline", str(baseline)]))

            plan = repo / "conformance/decomposition-plan.md"
            plan.parent.mkdir(parents=True)
            plan.write_text("# Plan\n", encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(0, main(["--repo", str(repo), "--baseline", str(baseline)]))

            source.write_text("\n" * 901, encoding="utf-8")
            with redirect_stderr(io.StringIO()):
                self.assertEqual(1, main(["--repo", str(repo), "--baseline", str(baseline)]))

    def test_strict_track_rejects_only_the_selected_legacy_track(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            source = repo / "src/core/legacy.zig"
            source.parent.mkdir(parents=True)
            source.write_text("\n" * 900, encoding="utf-8")
            plan = repo / "conformance/decomposition-plan.md"
            plan.parent.mkdir(parents=True)
            plan.write_text("# Plan\n", encoding="utf-8")
            baseline = repo / "baseline.json"
            write_baseline(baseline, scan(repo), track="deferred_todo")

            with redirect_stdout(io.StringIO()):
                self.assertEqual(0, main(["--repo", str(repo), "--baseline", str(baseline)]))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(0, main([
                    "--repo",
                    str(repo),
                    "--baseline",
                    str(baseline),
                    "--strict-track",
                    "active_native_backend",
                ]))

            errors = io.StringIO()
            with redirect_stderr(errors):
                self.assertEqual(1, main([
                    "--repo",
                    str(repo),
                    "--baseline",
                    str(baseline),
                    "--strict-track",
                    "deferred_todo",
                ]))
            self.assertIn("strict source track deferred_todo contains 1 finding(s)", errors.getvalue())

            source.write_text("\n" * 901, encoding="utf-8")
            with redirect_stderr(io.StringIO()):
                self.assertEqual(1, main(["--repo", str(repo), "--baseline", str(baseline)]))
            source.unlink()
            with redirect_stderr(io.StringIO()):
                self.assertEqual(1, main(["--repo", str(repo), "--baseline", str(baseline)]))


if __name__ == "__main__":
    unittest.main()
