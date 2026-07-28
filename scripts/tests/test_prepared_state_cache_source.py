from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
PREPARED_STATE_CACHE = (
    ROOT / "src" / "tools" / "metal_arena_plan" / "prepared_state_cache.zig"
)
PREPARED_GEOMETRY_CACHE = (
    ROOT / "src" / "tools" / "metal_arena_plan" / "prepared_geometry_cache.zig"
)
PREPARED_CACHE_TESTS = (
    ROOT / "src" / "tools" / "metal_arena_plan" / "prepared_cache_tests.zig"
)
MULTIPLICITY_FEEDS = (
    ROOT
    / "src"
    / "integrations"
    / "cairo_metal"
    / "resident"
    / "lookups"
    / "multiplicity_feeds.zig"
)
SESSION_CLI = ROOT / "src" / "tools" / "metal_prover_session" / "app.zig"


def ordered(source: str, *fragments: str) -> None:
    cursor = 0
    for fragment in fragments:
        next_cursor = source.find(fragment, cursor)
        if next_cursor < 0:
            raise AssertionError(f"missing ordered source fragment: {fragment!r}")
        cursor = next_cursor + len(fragment)


class PreparedStateCacheSourceContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.state_source = PREPARED_STATE_CACHE.read_text()
        cls.geometry_source = PREPARED_GEOMETRY_CACHE.read_text()
        cls.cache_test_source = PREPARED_CACHE_TESTS.read_text()
        cls.feed_source = MULTIPLICITY_FEEDS.read_text()
        cls.session_source = SESSION_CLI.read_text()

    def test_admission_covers_miss_commit_hit_key_switch_and_poison_recovery(self):
        ordered(
            self.cache_test_source,
            "PreparedStateAdmission.Decision.miss, try admission.begin(first, true)",
            "try admission.commit();",
            "PreparedStateAdmission.Decision.hit, try admission.begin(first, true)",
            "try admission.commit();",
            "PreparedStateAdmission.Decision.miss, try admission.begin(second, true)",
            "admission.poison();",
            "PreparedStateAdmission.Status.poisoned, admission.status",
            "PreparedStateAdmission.Decision.miss, try admission.begin(first, true)",
        )
        self.assertIn(
            ".pending, .borrowed => return error.PreparedStateAlreadyBorrowed",
            self.geometry_source,
        )
        self.assertIn(".empty, .poisoned => {}", self.geometry_source)

    def test_key_switch_miss_clears_only_resident_before_replacement_arena(self):
        cache_start = self.state_source.index("pub const PreparedStateCache")
        transition_start = self.state_source.index("    pub fn transition(\n", cache_start)
        transition_end = self.state_source.index("    pub fn begin(\n", transition_start)
        transition = self.state_source[transition_start:transition_end]
        ordered(
            transition,
            ".miss => {",
            "self.clearResidentResources();",
        )
        begin_start = transition_end
        begin_end = self.state_source.index("    pub fn capture(\n", begin_start)
        begin = self.state_source[begin_start:begin_end]
        ordered(
            begin,
            "const decision = try self.transition(",
            ".miss => {",
            "arena.ResidentArena.initByteLength",
        )

    def test_poison_clears_resident_and_only_the_active_geometry_transaction(self):
        cache_start = self.state_source.index("pub const PreparedStateCache")
        poison_start = self.state_source.index("    pub fn poison(", cache_start)
        poison_end = self.state_source.index("    pub fn requestTelemetry", poison_start)
        poison = self.state_source[poison_start:poison_end]
        ordered(
            poison,
            "self.admission.poison();",
            "self.clearResidentResources();",
            "self.geometry.poisonActive();",
        )

        clear_start = self.state_source.index("    pub fn clearResidentResources(", cache_start)
        clear_end = self.state_source.index("    pub fn compactSlot(", clear_start)
        clear = self.state_source[clear_start:clear_end]
        ordered(
            clear,
            "if (self.interaction_aot_witness) |*recipe| recipe.deinit();",
            "if (self.multiplicity_feeds) |*recipe| recipe.deinit();",
            "if (self.fixed_tables) |*recipe| recipe.deinit();",
            "if (self.base_aot_witness) |*recipe| recipe.deinit();",
            "if (self.snapshot) |*snapshot| snapshot.deinit();",
            "if (self.resident_arena) |*resident| resident.deinit();",
            "if (self.ranges.len != 0) self.allocator.free(self.ranges);",
            "self.base_aot_witness = null;",
            "self.snapshot = null;",
            "self.resident_arena = null;",
            "self.ranges = &.{};",
        )

        geometry = self.geometry_source
        self.assertIn("pub const prepared_geometry_capacity = 4;", geometry)
        self.assertIn(".hit => |raw_index| self.evictIndex(raw_index)", geometry)
        self.assertIn(".pending => |pending|", geometry)
        self.assertIn("owned.deinit();", geometry)
        self.assertNotIn("for (&self.entries)", geometry[geometry.index("fn poisonActive"):])

    def test_cached_feed_producer_names_are_owned(self):
        ordered(
            self.feed_source,
            "const producers = try allocator.alloc([]const u8, bundle.feeds.len);",
            "allocator.dupe(u8, bundle.feeds[producers_initialized].producer)",
            ".producers = producers,",
        )
        deinit_start = self.feed_source.index("pub const MultiplicityFeedBatch")
        deinit_start = self.feed_source.index("    pub fn deinit(", deinit_start)
        deinit_end = self.feed_source.index("\n    }", deinit_start)
        deinit = self.feed_source[deinit_start:deinit_end]
        ordered(
            deinit,
            "for (self.producers) |producer| self.allocator.free(producer);",
            "self.allocator.free(self.producers);",
        )

    def test_session_poison_window_covers_verification_commit_and_publication(self):
        ordered(
            self.session_source,
            "var prepared_state_borrowed = true;",
            "errdefer if (prepared_state_borrowed) prepared_state.poison();",
            "try one_shot.proveOnePreparedGeometry(",
            "if (!try boolField(cli_object, \"proof_verified\"))",
            "const proof_digest = try hashFile",
            "try prepared_state.commit();",
            "try publishOutputsExclusive(",
            "prepared_state_borrowed = false;",
        )
        ordered(
            self.session_source,
            "var prepared_geometry_borrowed = true;",
            "errdefer if (prepared_geometry_borrowed) prepared_host_geometry.poison();",
            "try one_shot.proveOnePreparedGeometry(",
            "if (!try boolField(cli_object, \"proof_verified\"))",
            "const proof_digest = try hashFile",
            "try prepared_host_geometry.validateCommit();",
            "try publishOutputsExclusive(",
            "prepared_host_geometry.commitAssumeValid();",
            "prepared_geometry_borrowed = false;",
        )


if __name__ == "__main__":
    unittest.main()
