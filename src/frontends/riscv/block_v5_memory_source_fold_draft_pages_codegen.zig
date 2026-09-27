const std = @import("std");
const Draft = @import("prover/block_v5_memory_source_fold_draft_pages_v1.zig");
const Store = @import("prover/block_v5_memory_source_fold_operand_store_v1.zig");
test "source fold draft pages bodies: original record publication load and bounded draft replay" {
    inline for (.{ &Draft.collect, &Draft.Reader.open, &Draft.Reader.next, &Draft.Reader.rewind, &Draft.Reader.requireFinished, &Draft.Owner.require, &Draft.Owner.promote, &Draft.Owner.deinit, &Store.publish, &Store.load }) |body| std.mem.doNotOptimizeAway(body);
}
