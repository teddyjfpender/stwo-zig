//! Dimension-only cost probe for the exact GKR verifier kernel. The sentinel
//! holds the heavy CPU maximum at26 layers. No new origin/proof is admitted;
//! source AIR projection, PCS and permutation/byte ownership remain pending.
const std = @import("std");
const C = @import("../../rv64_recursion/om31_poseidon/common.zig");
const Frame = @import("../../word16_global_execution/services/gkr_local/frame.zig");
const Template = @import("../pure_p2_gkr_template.zig");
const Child = @import("../full_p2_child.zig");
const Public = @import("../full_p2_frame.zig");
const G = @import("../../logup_gkr/om31_circuit_verifier.zig");
fn cost(a: std.mem.Allocator, instances: []const Frame.Instance) !struct { raw: [5]u64, native_mul: usize } {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const lengths = try arena.allocator().alloc(u8, try Template.count(instances));
    @memset(lengths, 4);
    const proof = try Template.skeleton(arena.allocator(), instances, lengths);
    var structural = C.lane.StructuralScope.init();
    defer structural.deinit();
    var scope = @import("scope.zig").begin();
    defer scope.deinit();
    var owner = try C.PoseidonContext.initTraceOnly(a, 0);
    defer owner.deinit();
    C.begin(&owner);
    var active = true;
    defer if (active) C.finish() catch {};
    const ctx = owner.algebra();
    var frame = Public.Frame.init(ctx);
    const statement = try frame.guessDigest(@splat(0));
    const ordinal = try frame.guessU32(0);
    var fixed: C.Hash = undefined;
    var main: C.Hash = undefined;
    for (&fixed, &main) |*f, *m| {
        f.* = try ctx.guess(C.Q.zero());
        m.* = try ctx.guess(C.Q.zero());
    }
    const wire = try G.wireProof(ctx, &proof);
    var pending = try Child.verify(ctx, .{ .statement = statement, .fixed = fixed, .main = main, .ordinal = ordinal.word }, instances, &wire);
    defer pending.artifact.deinit(a);
    try C.finish();
    active = false;
    try owner.finalize();
    return .{ .raw = try owner.rawCounts(), .native_mul = owner.native_mul_calls.items.len };
}
test "OP serialized sponge local GKR recursive dimension cost" {
    const a = std.testing.allocator;
    const sentinel = Frame.Instance{ .origin = .{ .core = .cpu }, .row_log = 22, .terms = 16, .fixed_offset = 0, .main_offset = 0 };
    const old = Frame.Instance{ .origin = .{ .sponge = .call }, .row_log = 7, .terms = 69, .fixed_offset = 0, .main_offset = 0 };
    var descriptor = old;
    descriptor.terms = 47;
    var state = old;
    state.row_log = 11;
    state.terms = 37;
    state.main_offset = 74;
    const permutation = Frame.Instance{ .origin = .{ .sponge = .perm }, .row_log = 8, .terms = 245, .fixed_offset = 0, .main_offset = 0 };
    var header = permutation;
    header.terms = 28;
    var word = permutation;
    word.terms = 28;
    word.row_log = 12;
    var lane = permutation;
    lane.terms = 25;
    lane.row_log = 13;
    const baseline = try cost(a, &.{ sentinel, old, permutation });
    const candidate = try cost(a, &.{ sentinel, descriptor, state, header, word, lane });
    const json = try std.json.Stringify.valueAlloc(a, .{ .scope = "GKR-kernel-only-synthetic-dimensions-no-binding-or-PCS", .common_layers = 26, .old = baseline, .candidate = candidate, .source_binding_tuple_coordinates = .{ .old_call = 105, .descriptor = 533, .state = 55, .old_permutation = 535, .header = 406, .word = 100, .lane = 113 }, .admission_closed = true }, .{});
    defer a.free(json);
    std.debug.print("OP_SPONGE_GKR_RECURSIVE_COST {s}\n", .{json});
}
