const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Sidecar = @import("../block_execution_sidecar_stark_v2.zig");
const Eval = @import("../block_v5_opcode_sidecar_eval_v1.zig");
const Integer = @import("../block_execution_integer_bridge_v2.zig");
const IntegerAlgebra = @import("../block_execution_integer_algebra_v1.zig");
const Caller = @import("../../air/guest_precompile/keccakf_caller.zig");
const Keccak = @import("../../air/guest_precompile/keccakf_trace.zig");

test "Keccak shared fixed clock keeps original packed access equations and masks" {
    const a = std.testing.allocator;
    const sealed = @import("../block_commitment_manifest.zig").Sealed{ .digest = @splat(91), .instance_count = 1 };
    const old_relations = try @import("../block_memory_relation_v2.zig").Challenges.draw(a, sealed);
    const relations = try @import("../block_v5_word_memory_protocol_v1.zig").Challenges.draw(a, sealed);
    const logs = try a.alloc(u32, Keccak.Layout.main_columns);
    defer a.free(logs);
    @memset(logs, 5);
    const fixed: [8]u32 = @splat(5);
    const descriptor = @import("../block_execution_external_trace_v2.zig").Descriptor{
        .kind = .keccak,
        .slot = 1,
        .log_size = 5,
        .fixed_offset = 0,
        .main_offset = 0,
        .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 10 },
    };
    var adapter = try (Sidecar.Component{
        .family = .base_alu_imm,
        .slot = 1,
        .external_source = descriptor,
        .log_size = 5,
        .base_clock = 0,
        .fixed_clock_offset = 0,
        .fixed_logs = &fixed,
        .main_logs = logs,
        .main_offset = 0,
        .shared_keccak_state_offset = Keccak.Layout.state,
        .transition_claim = Q.zero(),
        .transition_count = 1,
        .range_claims = @splat(Q.zero()),
        .challenges = &old_relations,
        .v5_universal = .{ .claim = Q.zero(), .elements = relations.universal_prefix.get(.memory_access) },
        .v5_packed = .{ .elements = &relations },
        .register_custody_mode = 1,
    }).init();
    const indices = try adapter.preprocessedColumnIndices(a);
    defer a.free(indices);
    try std.testing.expectEqualSlices(usize, &.{ 0, 1, 2, 3, 4, 5, 6, 7 }, indices);
    const component = adapter.asVerifierComponent();
    const components = core.air.components.Components{ .components = &.{component}, .n_preprocessed_columns = 8 };
    const point = core.circle.SECURE_FIELD_CIRCLE_GEN.mul(97);
    var masks = try components.maskPoints(a, point, 7, false);
    defer masks.deinitDeep(a);
    for (masks.items[0]) |column| {
        try std.testing.expectEqual(@as(usize, 1), column.len);
        try std.testing.expect(column[0].eql(point));
    }
    const output_point = point.add(@import("../../air/logup.zig").liftPoint(core.poly.circle.canonic.CanonicCoset.new(7).coset_value.step).mulSigned(27));
    try std.testing.expect(masks.items[1][Keccak.Layout.state][1].eql(output_point));
    const record = @import("../../runner/guest_precompile/keccakf_call_buffer.zig").Record{
        .execution_clock = 7,
        .pc = 1024,
        .state_ptr = 4096,
        .pointer_register = 4,
        .pointer_previous_clock = 1,
        .input = @splat(0),
        .output = @splat(0),
        .memory_previous_clocks = @splat(2),
    };
    const row = Caller.fill(record);
    var caller: [Caller.Layout.main_columns]Q = undefined;
    for (&caller, row) |*out, value| out.* = Q.fromBase(value);
    const bits: [32]Q = @splat(Q.zero());
    const pair = try @import("../block_execution_external_access_bridge_v2.zig").keccakPairFromWordBits(Q, &caller, bits, bits, 1);
    const clock: u64 = (1 << 40) + 400;
    const witness = try Integer.Witness.fromPair(pair, clock);
    const clock_bytes = IntegerAlgebra.clockBytes(Q, clock);
    var constant = adapter;
    constant.fixed_clock_offset = null;
    constant.base_clock = clock;
    const old = try Eval.evaluatePair(&constant, pair, witness.columns(), @splat(Q.zero()), @splat(Q.zero()));
    const shared = try Eval.evaluatePairWithClock(&adapter, pair, witness.columns(), @splat(Q.zero()), @splat(Q.zero()), clock_bytes);
    try std.testing.expectEqualDeep(old, shared);
    for (shared[0..Integer.RESIDUAL_COUNT]) |value| try std.testing.expect(value.isZero());
    var wrong_clock = clock_bytes;
    wrong_clock[5] = wrong_clock[5].add(Q.fromBase(M.one()));
    const changed = try Eval.evaluatePairWithClock(&adapter, pair, witness.columns(), @splat(Q.zero()), @splat(Q.zero()), wrong_clock);
    var rejected = false;
    for (changed[0..Integer.RESIDUAL_COUNT]) |value| rejected = rejected or !value.isZero();
    try std.testing.expect(rejected);
    adapter.register_custody_mode = 0;
    try std.testing.expectError(error.InvalidSharedKeccakClock, adapter.init());
    adapter.register_custody_mode = 1;
    adapter.fixed_clock_offset = 1;
    try std.testing.expectError(error.InvalidSharedKeccakClock, adapter.init());
    adapter.fixed_clock_offset = 0;
    adapter.base_clock = 1;
    try std.testing.expectError(error.InvalidSharedKeccakClock, adapter.init());
}
