const std = @import("std");
const Joint = @import("block_v7_memory_joint_proof_v1.zig");
test "v7 joint memory original lifecycle codegen" {
    inline for (.{ &Impl.Stage.init, &Impl.Stage.prove, &Impl.Stage.entry, &Impl.Stage.deinit, &Impl.verify }) |f| std.mem.doNotOptimizeAway(f);
}

const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Impl = Joint.For(Cpu);
const E = @import("block_v7_execution_epoch_v1.zig");
const Initial = @import("block_v7_initial_intervals_v1.zig");
const Terminal = @import("block_v7_terminal_protocol_v1.zig");
const Policy = @import("block_v7_execution_policy_v1.zig").Policy;
const Event = @import("../air/block/memory_transition.zig").Transition;
const Raw = @import("../runner/guest_precompile/test_elf.zig").buildReleaseProgram(1, &.{0x0000006f}, 64, .rv32im_zkvm_v1);
const elf = blk: {
    var bytes = Raw;
    const table = std.mem.readInt(u32, bytes[264..268], .little);
    for ([4]usize{ 2, 3, 7, 8 }, [4]u32{ 0x100100, 64, 0x100180, 0x100190 }) |index, value|
        std.mem.writeInt(u32, bytes[table + (index + 1) * 16 + 4 ..][0..4], value, .little);
    std.mem.writeInt(u32, bytes[644..648], 0x44332211, .little);
    break :blk bytes;
};
fn epochFor(policy: Policy, pin: E.Entry) !E.Epoch {
    var counts: E.Counts = @splat(0);
    counts[@intFromEnum(E.Family.memory_joint)] = 1;
    return E.Epoch.init(try policy.digest(), policy.config, counts, &.{pin}, 1);
}
fn guestSum(guest: []const Event, drawn: E.Drawn) !Q {
    var result = Q.zero();
    for (guest) |event| {
        var tuple: [11]Q = undefined;
        for (&tuple, @import("block_v5_word_memory_protocol_v1.zig").transitionTuple(event)) |*v, x| v.* = Q.fromBase(x);
        result = result.add(try drawn.memory.transition.combineSecure(tuple).inv());
    }
    return result;
}
test "v7 joint original memory STARK verifies detached and rejects compensated physical claims" {
    try run(false, false, false);
}
test "v7 joint memory independently keyed recursive parent" {
    try run(true, false, false);
}
test "v7 joint coefficient-backed inputs preserve exact original proof" {
    try run(false, true, false);
}
test "v7 joint coefficient interactions consume raw rows with exact proof parity" {
    try run(false, true, true);
}
fn run(comptime recursive_parent: bool, comptime compact_inputs: bool, comptime consume: bool) !void {
    const a = std.testing.allocator;
    var initialized = try Initial.Owned.derive(a, &elf, @import("block_v5_initial_sources_v1.zig").sha256(&elf), .rv32im_zkvm_v1, .{});
    defer initialized.deinit();
    var image = try @import("block_v7_program_image_v1.zig").Owned.init(a, &elf, &initialized, .{});
    defer image.deinit();
    var output: [43]u8 = undefined;
    for (&output, 0..) |*v, i| v.* = @intCast(i + 1);
    output[32] = 1;
    const policy = Policy{ .initialized = &initialized, .program_root = image.root.bytes, .terminal = .{ .final_cycle = 100, .halt_address = initialized.info.halt_flag, .length_address = initialized.info.output_len, .data_address = initialized.info.output_data, .output_end = initialized.info.output_end, .output = output }, .config = @import("../recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config() };
    const plan = try Terminal.Plan.init(policy.terminal);
    var guest: [16]Event = undefined;
    for (guest[0..13], 0..) |*event, i| {
        const read = try plan.transition(i, 0xa5);
        event.* = .{ .space = 1, .address = read.address, .clock = if (read.address == initialized.info.halt_flag) 4 * (policy.terminal.final_cycle - 1) + 1 else 4 * (i / 3) + i % 3 + 1, .before = (try initialized.find(read.address)).value, .after = read.before };
    }
    guest[13] = .{ .space = 1, .address = 0x100100, .clock = 21, .before = (try initialized.find(0x100100)).value, .after = 19 };
    guest[14] = .{ .space = 1, .address = 0x100100, .clock = 22, .before = 19, .after = 23 };
    guest[15] = .{ .space = 1, .address = initialized.info.input_start, .clock = 23, .before = 0xdeadbeef, .after = 7 };
    const stage = try Impl.Stage.init(a, policy, &guest, 0xa5, 7, .{ .input_storage = if (compact_inputs) .{ .coefficients = .{ .minimum_trace_log = 4 } } else .resident, .interaction_storage = if (consume) .{ .coefficients = .{ .minimum_trace_log = 4 } } else .resident, .consume_rows = consume });
    const input_live_bytes = stage.budget.snapshot().live_bytes;
    var stage_live = true;
    defer if (stage_live) stage.deinit();
    try std.testing.expectEqual(@as(usize, 8), stage.layout.parts.len);
    if (compact_inputs) for (stage.scheme.trees.items) |tree| {
        try std.testing.expect(tree.compact_polynomials);
        for (tree.columns) |column| {
            try std.testing.expectEqual(@as(usize, 0), column.values.len);
            try std.testing.expect(column.coefficient_values != null);
        }
    };
    const pin = try stage.entry();
    const epoch = try epochFor(policy, pin);
    try std.testing.expectError(error.IncompleteV7Epoch, epoch.requireCompleteFamilies()); // scoped memory proof, not execution
    var proof = try stage.prove(epoch, &.{pin});
    defer proof.deinit();
    if (consume) {
        try std.testing.expect(!stage.witness_live);
        try std.testing.expectError(error.InvalidV7JointPhase, stage.prove(epoch, &.{pin}));
        try std.testing.expectError(error.InvalidV7JointPhase, stage.releaseWitness());
    }
    if (compact_inputs) {
        const resident = try Impl.Stage.init(a, policy, &guest, 0xa5, 7, .{});
        defer resident.deinit();
        const resident_input_live_bytes = resident.budget.snapshot().live_bytes;
        try std.testing.expect(input_live_bytes < resident_input_live_bytes);
        try std.testing.expectEqualDeep(pin, try resident.entry());
        var oracle = try resident.prove(epoch, &.{pin});
        defer oracle.deinit();
        try std.testing.expectEqualDeep(oracle.claims(), proof.claims());
        var left = std.Io.Writer.Allocating.init(a);
        defer left.deinit();
        var right = std.Io.Writer.Allocating.init(a);
        defer right.deinit();
        const postcard = @import("interop_postcard");
        try postcard.serializeProof(core.proof_suites.Blake3.Hasher, &left.writer, oracle.stark);
        try postcard.serializeProof(core.proof_suites.Blake3.Hasher, &right.writer, proof.stark);
        try std.testing.expectEqualSlices(u8, left.written(), right.written());
        std.debug.print("V7_JOINT_INPUT_STORAGE coefficient_backed=true byte_identical=true input_lde_cells_retained=0 compact_input_live_bytes={d} resident_input_live_bytes={d} proof_bytes={d}\n", .{ input_live_bytes, resident_input_live_bytes, right.written().len });
    }
    stage.deinit();
    stage_live = false;
    // Reconstruct the actual STARK through its canonical wire format after the
    // producer matrices and commitment scheme have been destroyed.
    var writer = std.Io.Writer.Allocating.init(proof.allocator);
    defer writer.deinit();
    const wire = @import("interop_postcard");
    try wire.serializeProof(core.proof_suites.Blake3.Hasher, &writer.writer, proof.stark);
    var reader = std.io.fixedBufferStream(writer.written());
    const rebuilt = try wire.deserializeProof(core.proof_suites.Blake3.Hasher, proof.allocator, reader.reader());
    proof.stark.deinit(proof.allocator);
    proof.stark = rebuilt;
    try std.testing.expectEqual(writer.written().len, reader.pos);
    var captured = try Impl.verifyAndCapture(a, policy, epoch, &.{pin}, &proof, .{});
    defer captured.deinit();
    const open = captured.open;
    try @import("tests/block_v7_joint_recursive_test_support.zig").qualify(a, .{ .policy = policy, .epoch = epoch, .roster = &.{pin}, .roots = proof.roots, .interval_log = proof.interval_log, .claims = proof.claims() }, &captured, recursive_parent);
    try std.testing.expectEqual(@as(u64, guest.len), open.event_count);
    try std.testing.expect(open.transition.add(try guestSum(&guest, try epoch.draw(a))).isZero());
    // Preserve aggregated range closure while forging two physical claims.
    const saved_ram = proof.ram[0].sums[3];
    const saved_range = proof.range16[0];
    proof.ram[0].sums[3] = saved_ram.add(Q.one());
    proof.range16[0] = saved_range.sub(Q.one());
    _ = try @import("block_v7_memory_joint_protocol_v1.zig").closeVerifiedClaims(proof.claims());
    try std.testing.expectError(error.OodsNotMatching, Impl.verify(a, policy, epoch, &.{pin}, &proof, .{}));
    proof.ram[0].sums[3] = saved_ram;
    proof.range16[0] = saved_range;
    // Preserve the total transition sum while mutating two component claims.
    const left = proof.ram[0].sums[0];
    const right = proof.ram[1].sums[0];
    proof.ram[0].sums[0] = left.add(Q.one());
    proof.ram[1].sums[0] = right.sub(Q.one());
    try std.testing.expectError(error.OodsNotMatching, Impl.verify(a, policy, epoch, &.{pin}, &proof, .{}));
    proof.ram[0].sums[0] = left;
    proof.ram[1].sums[0] = right;
    std.mem.swap(@import("block_v7_memory_joint_air_v1.zig").RamClaim, &proof.ram[0], &proof.ram[1]);
    try std.testing.expectError(error.InvalidV5RamLanesCensus, Impl.verify(a, policy, epoch, &.{pin}, &proof, .{}));
    std.mem.swap(@import("block_v7_memory_joint_air_v1.zig").RamClaim, &proof.ram[0], &proof.ram[1]);
    const old_root = proof.roots[0];
    proof.roots[0][0] ^= 1;
    try std.testing.expectError(error.UntrustedV7SourceEntry, Impl.verify(a, policy, epoch, &.{pin}, &proof, .{}));
    proof.roots[0] = old_root;
    std.debug.print("V7_MEMORY_JOINT verified=true original_proofs=1 ram_shards=5 providers=3 guest_events=16 terminal_reads=13 proof_bytes={d} producer_rows=0 compensated_claims_rejected=true full_execution=false\n", .{writer.written().len});
}
