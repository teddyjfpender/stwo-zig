from __future__ import annotations

import json
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from scripts.typed_air_work_site_authority import (
    AuthorityError,
    AuthoritySpec,
    CallSpec,
    LiteralShape,
    SCHEMA,
    SiteSpec,
    check_authority,
    check_manifest,
    main,
)


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "scripts/tests/fixtures/typed_air_work_site_authority"


def fixture_spec() -> AuthoritySpec:
    return AuthoritySpec(
        sites=(
            SiteSpec("alpha", ("plan.zig",), ("complete.zig",)),
            SiteSpec("beta", ("plan.zig",), ("complete.zig",)),
        ),
        sources=("complete.zig", "plan.zig"),
        completion_calls=(
            CallSpec(
                "recordCompletedDelta",
                LiteralShape.NAMED_FIELD,
                "site",
            ),
        ),
    )


def valid_sources() -> dict[str, str]:
    return {
        "plan.zig": """
            fn expectProducer(site: Site) void { _ = site; }
            fn plan(recorder: anytype) !void {
                try recorder.expectProducer(.alpha);
                try recorder.expectProducer(.beta);
            }
        """,
        "complete.zig": """
            fn recordCompletedDelta(delta: anytype) void { _ = delta; }
            fn complete(recorder: anytype) !void {
                try recorder.recordCompletedDelta(.{ .site = .alpha });
                try recorder.recordCompletedDelta(.{ .site = .beta });
            }
        """,
    }


class TypedAirWorkSiteAuthorityTests(unittest.TestCase):
    def test_tracked_fixture_passes_with_deterministic_report(self) -> None:
        report = check_manifest(FIXTURE / "authority.json")
        canonical = report.canonical()
        self.assertEqual(canonical["schema"], SCHEMA)
        self.assertEqual(canonical["registered_site_count"], 2)
        self.assertEqual(canonical["plan_occurrence_count"], 2)
        self.assertEqual(canonical["completion_occurrence_count"], 2)
        self.assertEqual(
            [item["site"] for item in canonical["occurrences"]],
            ["alpha_fft", "alpha_fft", "beta_fri", "beta_fri"],
        )
        self.assertEqual(
            json.dumps(canonical, sort_keys=True),
            json.dumps(check_manifest(FIXTURE / "authority.json").canonical(), sort_keys=True),
        )

    def test_cli_accepts_the_tracked_fixture(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main([str(FIXTURE / "authority.json")]), 0)
        self.assertEqual(json.loads(output.getvalue())["registered_site_count"], 2)

    def test_joint_plan_and_completion_deletion_is_rejected(self) -> None:
        sources = valid_sources()
        sources["plan.zig"] = sources["plan.zig"].replace(
            "try recorder.expectProducer(.alpha);", ""
        )
        sources["complete.zig"] = sources["complete.zig"].replace(
            "try recorder.recordCompletedDelta(.{ .site = .alpha });", ""
        )
        with self.assertRaises(AuthorityError) as captured:
            check_authority(fixture_spec(), sources)
        self.assertIn(".alpha is missing its plan call", str(captured.exception))
        self.assertIn(".alpha is missing its completion call", str(captured.exception))

    def test_registered_site_substitution_is_rejected(self) -> None:
        sources = valid_sources()
        sources["plan.zig"] = sources["plan.zig"].replace(".alpha", ".beta")
        with self.assertRaises(AuthorityError) as captured:
            check_authority(fixture_spec(), sources)
        self.assertIn(".alpha is missing its plan call", str(captured.exception))
        self.assertIn(".beta has duplicate plan calls", str(captured.exception))

    def test_unregistered_plan_and_completion_literals_are_rejected(self) -> None:
        sources = valid_sources()
        sources["plan.zig"] += "\nfn extra(r: anytype) !void { try r.expectProducer(.gamma); }\n"
        sources["complete.zig"] += (
            "\nfn extra(r: anytype) !void { "
            "try r.recordCompletedDelta(.{ .site = .gamma }); }\n"
        )
        with self.assertRaises(AuthorityError) as captured:
            check_authority(fixture_spec(), sources)
        message = str(captured.exception)
        self.assertIn("unregistered plan site .gamma", message)
        self.assertIn("unregistered completion site .gamma", message)

    def test_duplicate_plan_and_completion_calls_are_rejected(self) -> None:
        sources = valid_sources()
        sources["plan.zig"] += "\nfn extra(r: anytype) !void { try r.expectProducer(.alpha); }\n"
        sources["complete.zig"] += (
            "\nfn extra(r: anytype) !void { "
            "try r.recordCompletedDelta(.{ .site = .alpha }); }\n"
        )
        with self.assertRaises(AuthorityError) as captured:
            check_authority(fixture_spec(), sources)
        message = str(captured.exception)
        self.assertIn(".alpha has duplicate plan calls", message)
        self.assertIn(".alpha has duplicate completion calls", message)

    def test_nested_configured_call_cannot_hide_a_duplicate(self) -> None:
        sources = valid_sources()
        sources["complete.zig"] += """
            fn nested(recorder: anytype) !void {
                try recorder.recordCompletedDelta(.{
                    .site = .alpha,
                    .delta = recorder.expectProducer(.alpha),
                });
            }
        """
        with self.assertRaises(AuthorityError) as captured:
            check_authority(fixture_spec(), sources)
        message = str(captured.exception)
        self.assertIn(".alpha has duplicate plan calls", message)
        self.assertIn(".alpha has duplicate completion calls", message)

    def test_comments_and_all_zig_string_forms_cannot_replace_calls(self) -> None:
        inert = r'''
            // expectProducer(.alpha)
            /* recordCompletedDelta(.{ .site = .alpha }) */
            const regular = "expectProducer(.alpha)";
            const character = 'x';
            const multiline =
                \\recordCompletedDelta(.{ .site = .alpha })
            ;
        '''
        sources = {"plan.zig": inert, "complete.zig": inert}
        with self.assertRaises(AuthorityError) as captured:
            check_authority(
                AuthoritySpec(
                    sites=(SiteSpec("alpha"),),
                    sources=("complete.zig", "plan.zig"),
                    completion_calls=fixture_spec().completion_calls,
                ),
                sources,
            )
        message = str(captured.exception)
        self.assertIn("missing its plan call", message)
        self.assertIn("missing its completion call", message)
        self.assertNotIn("unregistered", message)

    def test_dynamic_plan_value_is_not_a_typed_site_literal(self) -> None:
        sources = valid_sources()
        sources["plan.zig"] = sources["plan.zig"].replace(
            "expectProducer(.alpha)", "expectProducer(site)"
        )
        with self.assertRaisesRegex(AuthorityError, "one bare enum literal"):
            check_authority(fixture_spec(), sources)

    def test_completion_helper_can_bind_an_indexed_enum_argument(self) -> None:
        spec = AuthoritySpec(
            sites=(SiteSpec("alpha"),),
            sources=("source.zig",),
            completion_calls=(
                CallSpec(
                    "recordCompletedWork",
                    LiteralShape.ENUM_ARGUMENT,
                    argument=1,
                ),
            ),
        )
        report = check_authority(
            spec,
            {
                "source.zig": """
                    fn run(recorder: anytype, delta: anytype) !void {
                        try recorder.expectProducer(.alpha);
                        try recordCompletedWork(recorder, .alpha, .{
                            .nested = call(1, 2),
                            .delta = delta,
                        });
                    }
                """
            },
        )
        self.assertEqual(len(report.occurrences), 2)

    def test_indexed_enum_argument_rejects_dynamic_or_missing_value(self) -> None:
        spec = AuthoritySpec(
            sites=(SiteSpec("alpha"),),
            sources=("source.zig",),
            completion_calls=(
                CallSpec(
                    "recordCompletedWork",
                    LiteralShape.ENUM_ARGUMENT,
                    argument=1,
                ),
            ),
        )
        for call, message in (
            ("recordCompletedWork(recorder)", "has no site argument 1"),
            (
                "recordCompletedWork(recorder, selected_site, delta)",
                "argument 1 must be one bare enum literal",
            ),
        ):
            source = (
                "fn run(recorder: anytype, delta: anytype) !void { "
                "try recorder.expectProducer(.alpha); try " + call + "; }"
            )
            with self.subTest(call=call), self.assertRaisesRegex(
                AuthorityError, message
            ):
                check_authority(spec, {"source.zig": source})

    def test_dynamic_completed_delta_value_is_not_a_typed_site_literal(self) -> None:
        sources = valid_sources()
        sources["complete.zig"] = sources["complete.zig"].replace(
            ".site = .alpha", ".site = site"
        )
        with self.assertRaisesRegex(AuthorityError, "one \\.site = \\.site literal"):
            check_authority(fixture_spec(), sources)

    def test_path_ownership_rejects_cross_file_site_movement(self) -> None:
        sources = valid_sources()
        sources["plan.zig"] = sources["plan.zig"].replace(
            "try recorder.expectProducer(.alpha);", ""
        )
        sources["complete.zig"] += (
            "\nfn misplaced(r: anytype) !void { try r.expectProducer(.alpha); }\n"
        )
        with self.assertRaisesRegex(AuthorityError, "allowed=\\['plan.zig'\\]"):
            check_authority(fixture_spec(), sources)

    def test_source_inventory_is_closed(self) -> None:
        sources = valid_sources()
        sources["unregistered.zig"] = "try r.expectProducer(.alpha);"
        with self.assertRaisesRegex(AuthorityError, "source inventory drifted"):
            check_authority(fixture_spec(), sources)

    def test_manifest_rejects_unsorted_or_duplicate_registry(self) -> None:
        for sites, message in (
            ((SiteSpec("beta"), SiteSpec("alpha")), "sorted"),
            ((SiteSpec("alpha"), SiteSpec("alpha")), "duplicates"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(
                AuthorityError, message
            ):
                check_authority(
                    AuthoritySpec(
                        sites=sites,
                        sources=("source.zig",),
                        completion_calls=fixture_spec().completion_calls,
                    ),
                    {"source.zig": ""},
                )

    def test_manifest_loader_rejects_source_path_escape(self) -> None:
        manifest = {
            "schema": SCHEMA,
            "source_root": ".",
            "sources": ["../escape.zig"],
            "sites": [{"name": "alpha"}],
            "plan_calls": [
                {
                    "name": "expectProducer",
                    "shape": "enum_argument",
                    "argument": 0,
                }
            ],
            "completion_calls": [
                {
                    "name": "recordCompletedDelta",
                    "shape": "named_field",
                    "field": "site",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authority.json"
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(AuthorityError, "normalized POSIX"):
                check_manifest(path)


if __name__ == "__main__":
    unittest.main()
