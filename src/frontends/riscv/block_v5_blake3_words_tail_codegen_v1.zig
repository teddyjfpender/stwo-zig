//! Actual source/witness/preprocessing bodies retained; never invoked here.
const std = @import("std");
const Tail = @import("recursion/blake3_words_tail_v1.zig");
const Schedule = @import("recursion/air/blake3_words_tail_plan_v1.zig");
const Witness = @import("recursion/air/blake3_words_tail_witness_v1.zig");
const Hash = @import("recursion/air/blake3_hash_plan.zig");
pub export fn stwo_original_words_tail_body_gate() void {
    inline for (.{ &Hash.build, &Hash.buildSubtreeAt, &Hash.buildPrefixFold, &Tail.Geometry.init, &Tail.Geometry.require, &Tail.WordsView.init, &Tail.WordsView.read, &Tail.chunk, &Tail.subtree, &Tail.ScalarTail.init, &Tail.ScalarTail.fold, &Tail.ScalarTail.deinit, &Schedule.Plan.init, &Schedule.Plan.require, &Schedule.Plan.deinit, &Witness.Statement.require, &Witness.prepare, &Witness.trusted, &Witness.Prepared.deinit }) |body| std.mem.doNotOptimizeAway(body);
}
