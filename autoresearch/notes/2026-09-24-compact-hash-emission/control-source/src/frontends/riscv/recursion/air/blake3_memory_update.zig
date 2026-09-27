//! One word update: both roots use one address and a single sibling producer.
//! Production admission must authenticate the old/new byte sources and roots.
const std = @import("std");
const core = @import("stwo_core");
const tree = @import("../../air/memory_commitment/blake3_state_tree.zig");
const path = @import("blake3_memory_path.zig");
const Caller = @import("blake3_memory_leaf.zig").Caller;
pub const Statement = struct {
    namespace: u32,
    kind: tree.Kind,
    address: u32,
    before_source: Caller,
    after_source: Caller,
    before_root: tree.Digest,
    after_root: tree.Digest,
};
pub const Prepared = struct {
    before: path.Prepared,
    after: path.Prepared,
    pub fn deinit(self: *Prepared) void {
        self.after.deinit();
        self.before.deinit();
        self.* = undefined;
    }
};
pub fn prepare(a: std.mem.Allocator, statement: Statement, before: u32, after: u32, siblings: *const [tree.DEPTH]tree.Digest) !Prepared {
    return build(a, statement, .{ .before = before, .after = after, .siblings = siblings });
}
pub fn trusted(a: std.mem.Allocator, statement: Statement) !Prepared {
    return build(a, statement, null);
}
const Witness = struct { before: u32, after: u32, siblings: *const [tree.DEPTH]tree.Digest };
fn build(a: std.mem.Allocator, s: Statement, witness: ?Witness) !Prepared {
    const path_width = 2 * tree.DEPTH + 1;
    const end = @as(u64, s.namespace) + 2 * path_width + tree.DEPTH - 1;
    if (end >= core.fields.m31.Modulus or std.meta.eql(s.before_source, s.after_source)) return error.InvalidMemoryUpdate;
    for ([_]Caller{ s.before_source, s.after_source }) |source| {
        if (source.circuit >= core.fields.m31.Modulus or source.wire >= core.fields.m31.Modulus or
            (source.circuit >= s.namespace and source.circuit <= end)) return error.InvalidMemoryUpdate;
    }
    const sibling_namespace = s.namespace + 2 * path_width;
    const before_statement = path.Statement{ .namespace = s.namespace, .sibling_namespace = sibling_namespace, .source = s.before_source, .kind = s.kind, .address = s.address, .root = s.before_root };
    const after_statement = path.Statement{ .namespace = s.namespace + path_width, .sibling_namespace = sibling_namespace, .source = s.after_source, .kind = s.kind, .address = s.address, .root = s.after_root };
    var before = if (witness) |w| try path.prepare(a, before_statement, w.before, w.siblings) else try path.trusted(a, before_statement);
    errdefer before.deinit();
    var after = if (witness) |w| try path.prepare(a, after_statement, w.after, w.siblings) else try path.trusted(a, after_statement);
    errdefer after.deinit();
    if (before.word_rows.len != after.word_rows.len) return error.InvalidMemoryUpdate;
    for (before.word_rows, after.word_rows) |*producer, duplicate| {
        for (producer[0..7], duplicate[0..7]) |left, right| if (!left.eql(right)) return error.InvalidMemoryUpdate;
        const uses = try std.math.add(u32, producer[7].toU32(), duplicate[7].toU32());
        if (uses >= core.fields.m31.Modulus) return error.InvalidMemoryUpdate;
        producer[7] = core.fields.m31.M31.fromCanonical(uses);
    }
    // The after arena retains storage ownership; only its emitted row view is empty.
    after.word_rows = after.word_rows[0..0];
    return .{ .before = before, .after = after };
}
