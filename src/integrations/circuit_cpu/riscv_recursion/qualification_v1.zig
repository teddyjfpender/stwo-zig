//! Deferred qualification campaign. No generated key/hash is blessed here.
//! The heavy genuine gate is opt-in and MUST wait for the live full run.
const std = @import("std");
const core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const Registry = @import("registry_v1.zig");
const Authority = @import("authority_v1.zig");
const Material = @import("proof_material_v1.zig");
const Leaf = @import("leaf_wrap_v1.zig");
const Upper = @import("../../../frontends/riscv/recursion/block_v8_window_root_receiver_v1.zig");
const Wire = @import("../../../frontends/riscv/recursion/block_v8_window_root_wire_v1.zig");
const Capture = @import("../../../frontends/riscv/prover/block_v7_real_window_capture_v1.zig");
const Full = @import("../../../frontends/riscv/prover/block_v8_full_boundary_policy_v1.zig");
const Recorder = @import("../../../frontends/riscv/recursion/air/composition_graph_recorder.zig");
const Q = core.fields.qm31.QM31;

test "RISC circuit lowering preserves canonical field inverse and zero anchors" {
    const a = std.testing.allocator;
    var graph = Recorder.Builder.init(a);
    defer graph.deinit();
    const x = try graph.input();
    const y = try graph.input();
    try graph.activate();
    try graph.constrainZero(x.value.mul(y.value).sub(Recorder.Scalar.one()));
    try graph.constrainZero(x.value.inverse().sub(y.value));
    graph.deactivate();
    var compiled = try graph.finish();
    defer compiled.deinit();
    inline for (.{ true, false }) |valid| {
        var ctx = try circuit.builder.Context(Q).init(a, 0);
        defer ctx.deinit();
        const value = Q.fromU32Unchecked(7, 9, 3, 1);
        const wires = [_]circuit.builder.Var{ try ctx.guess(value), try ctx.guess(if (valid) try value.inv() else Q.one()) };
        try circuit.builder.riscv_composition_lowering_v1.constrain(Q, &ctx, &compiled, &wires);
        try ctx.finalize(true);
        try std.testing.expectEqual(valid, try ctx.isCircuitValid());
    }
}

test "RISC circuit registry rejects nominated outer equation authorities" {
    try std.testing.expectError(error.UntrustedRiscCircuitEquationArtifact, Registry.BackendAuthority.load(std.testing.allocator, "not circuit AIR", "not a projection"));
}

test "RISC circuit liveness preserves input ordinals and direct zero anchors" {
    const a = std.testing.allocator;
    const Lower = circuit.builder.riscv_composition_lowering_v1;
    var graph = Recorder.Builder.init(a);
    defer graph.deinit();
    _ = try graph.input();
    const used = try graph.input();
    try graph.activate();
    try graph.constrainZero(used.value);
    graph.deactivate();
    var compiled = try graph.finish();
    defer compiled.deinit();
    var live = try Lower.liveness(a, &compiled);
    defer live.deinit(a);
    try std.testing.expectEqualSlices(bool, &.{ false, true }, live.inputs);
    var ctx = try circuit.builder.Context(Q).init(a, 0);
    defer ctx.deinit();
    const actual = try ctx.guess(Q.zero());
    try Lower.constrain(Q, &ctx, &compiled, &.{ ctx.one(), actual });
    try ctx.finalize(true);
    try std.testing.expect(try ctx.isCircuitValid());
    ctx.value_table.items[actual.idx] = Q.one();
    try std.testing.expect(!try ctx.isCircuitValid());
}

test "RISC circuit liveness retains nonzero guards of unused inverse results" {
    const a = std.testing.allocator;
    const Lower = circuit.builder.riscv_composition_lowering_v1;
    var graph = Recorder.Builder.init(a);
    defer graph.deinit();
    const denominator = try graph.input();
    try graph.activate();
    _ = denominator.value.inverse();
    try graph.constrainZero(Recorder.Scalar.zero());
    graph.deactivate();
    var compiled = try graph.finish();
    defer compiled.deinit();
    var live = try Lower.liveness(a, &compiled);
    defer live.deinit(a);
    try std.testing.expectEqualSlices(bool, &.{true}, live.inputs);
    const scratch = try a.alloc(Q, compiled.nodes.len);
    defer a.free(scratch);
    try std.testing.expectError(error.DivisionByZero, compiled.evaluateInto(&.{Q.zero()}, scratch));
    var ctx = try circuit.builder.Context(Q).init(a, 0);
    defer ctx.deinit();
    const value = try ctx.guess(Q.fromU32Unchecked(9, 0, 0, 0));
    try Lower.constrain(Q, &ctx, &compiled, &.{value});
    try ctx.finalize(true);
    try std.testing.expect(try ctx.isCircuitValid());
    ctx.value_table.items[value.idx] = Q.zero();
    try std.testing.expect(!try ctx.isCircuitValid());
}

test "RISC Blake3 digest and full XOF satisfy canonical gate multiplicities" {
    const a = std.testing.allocator;
    const b = circuit.builder;
    const Word = b.wrappers.U32Wrapper(b.Var);
    const primitive = b.blake3_reuse_v1;
    const cv = core.crypto.blake3_compression.IV;
    var block: [16]u32 = undefined;
    for (&block, 0..) |*word, i| word.* = @intCast(11 * i + 5);
    const flags: u32 = primitive.CHUNK_START | primitive.CHUNK_END | primitive.ROOT;
    const expected = try core.crypto.blake3_compression.compress(cv, block, 0, 64, flags);
    inline for (.{ true, false }) |full_xof| {
        var ctx = try b.Context(Q).init(a, 0);
        defer ctx.deinit();
        var cv_words: [8]Word = undefined;
        var block_words: [16]Word = undefined;
        for (&cv_words, cv) |*word, value| word.* = try b.wrappers.guessU32(Q, &ctx, b.wrappers.u32Value(Q, value));
        for (&block_words, block) |*word, value| word.* = try b.wrappers.guessU32(Q, &ctx, b.wrappers.u32Value(Q, value));
        const result = if (full_xof)
            try primitive.compress(Q, &ctx, cv_words, block_words, 0, 64, flags)
        else
            try primitive.compressDigest(Q, &ctx, cv_words, block_words, 0, 64, flags);
        try std.testing.expectEqual(@as(usize, if (full_xof) 16 else 8), ctx.circuit.triple_xor.items.len);
        for (result, expected[0..result.len]) |actual, value|
            try ctx.eq(actual.get(), (try b.wrappers.constU32(Q, &ctx, value)).get());
        try ctx.finalize(true);
        try std.testing.expect(try ctx.isCircuitValid());
        const targets = circuit.common.finalize.computePaddedSizes(.fromBuilder(&ctx.circuit));
        try circuit.common.finalize.padToTargets(Q, &ctx, targets);
        // This is the actual AIR preprocessing invariant, beyond arithmetic
        // replay: each G row's four output multiplicities must agree.
        var preprocessed = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(a, &ctx.circuit);
        defer preprocessed.deinit(a);
    }
}

test "RISC complete native-parent circuit wrapper genuine q70 fresh bytes and hostile material" {
    if (!std.process.hasEnvVarConstant("STWO_RISCV_NATIVE_PARENT_CIRCUIT_Q70")) return error.SkipZigTest;
    try qualify(false);
}
test "RISC valid PCS and public supply invalid typed AIR rejected by actual complete leaf q70" {
    if (!std.process.hasEnvVarConstant("STWO_RISCV_CIRCUIT_AIR_INVALID_Q70")) return error.SkipZigTest;
    try qualify(true);
}
fn qualify(comptime air_invalid_only: bool) !void {
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 48 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var scratch = std.heap.ArenaAllocator.init(a);
    defer scratch.deinit();
    const t = scratch.allocator();
    const elf = tinyElf();
    var captured = try Capture.capture(a, &elf, &.{}, .{ .elf = Capture.sha(&elf), .input = Capture.sha(&.{}) }, .{ .skip_cycles = 0, .cycles = 4 }, .{});
    defer captured.deinit();
    captured.releaseExecution();
    const config = @import("../../../frontends/riscv/recursion/blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    var expected: [43]u8 = @splat(0);
    expected[32] = 1;
    var full = try Full.Owned.derive(a, &elf, &.{}, .{ .elf_sha256 = Capture.sha(&elf), .input_sha256 = Capture.sha(&.{}), .total_cycles = 7, .expected_output = expected, .config = config }, .{});
    defer full.deinit();
    var directory = try std.fs.cwd().openDir("campaign/qualification/new-full-block-depth2-driver-q70-v1", .{});
    defer directory.close();
    const public_bytes = try directory.readFileAlloc(t, "node-0.public", 128 << 20);
    const input = try Wire.decodeNativeLeafLeaky(t, public_bytes, .{});
    const metadata = Upper.Tree{ .leaf = .{ .input = input, .external = .{ .elf = &elf, .config = config, .incoming = captured.incoming, .outgoing = captured.outgoing, .trusted = .{ .elf_sha256 = Capture.sha(&elf), .incoming_sha256 = captured.incoming.identity(), .outgoing_sha256 = captured.outgoing.identity(), .window = .{ .skip_cycles = 0, .cycles = 4 } }, .boundary = try full.windowOptions(0, 4) } } };
    if (air_invalid_only) {
        try @import("invalid_air_fixture_v1.zig").qualify(a, metadata);
        return;
    }
    const air = try std.fs.cwd().readFileAlloc(t, "vectors/circuit/official/circuit_air.air_programs_v1.bin", 1 << 20);
    const projection = try std.fs.cwd().readFileAlloc(t, "vectors/circuit/official/compiled_air_constraints_v1.bin", 1 << 20);
    const backend = try Registry.BackendAuthority.load(a, air, projection);
    defer backend.deinit();
    const artifact = blk: {
        const native = try directory.readFileAlloc(a, "node-0.proof", 64 << 20);
        defer a.free(native);
        break :blk try Registry.produce(a, metadata, native, backend, .{});
    };
    var result = artifact;
    defer result.deinit();
    // The native proof and all producer keys/material are already destroyed.
    // Receiver compiles from external pins + public metadata and raw outer bytes.
    try Registry.verifyBytes(a, metadata, result.bytes, backend, .{});
    const native = try directory.readFileAlloc(a, "node-0.proof", 64 << 20);
    defer a.free(native);
    var authority = try Authority.Owned.derive(a, metadata);
    defer authority.deinit();
    var material = try Material.Owned.fromBytes(a, native, &authority);
    defer material.deinit();
    // These are direct witness corruptions AFTER the PCS expansion gate.
    // A native receipt therefore cannot authorize their circuit assignments.
    material.claims[0] = material.claims[0].add(Q.one());
    material.claims[1] = material.claims[1].sub(Q.one());
    {
        var ctx = try circuit.builder.Context(Q).init(a, Leaf.OUTPUTS);
        defer ctx.deinit();
        ctx.assert_eq_on_eval = true;
        try std.testing.expectError(error.RiscCircuitTypedCompositionRejected, Leaf.build(Q, &ctx, &authority, &material));
    }
    material.claims[0] = material.claims[0].sub(Q.one());
    material.claims[1] = material.claims[1].add(Q.one());
    material.material.commitments[1][0] ^= 1;
    {
        var ctx = try circuit.builder.Context(Q).init(a, Leaf.OUTPUTS);
        defer ctx.deinit();
        ctx.assert_eq_on_eval = true;
        try std.testing.expectError(error.EqFailedOnEval, Leaf.build(Q, &ctx, &authority, &material));
    }
    std.debug.print("RISC_CIRCUIT_NATIVE_PARENT q70=70 pow=26 typed_air=23 tables=2 physical_claims=25 relation_pairs=47 trace_trees=4 fresh_outer_bytes=true bytes={d}\n", .{result.bytes.len});
}

// The already qualified seven-instruction fixture; no original proof is
// regenerated by the circuit gate. Only four boundary instructions are replayed.
const tiny_code = [_]u32{ 0x001000b7, 0x10008093, 0x02b00113, 0x0020a223, 0x00100113, 0x0220a423, 0x0020a023, 0x0000006f };
pub fn tinyElf() @TypeOf(@import("../../../frontends/riscv/runner/guest_precompile/test_elf.zig").buildReleaseProgram(tiny_code.len, &tiny_code, 256, .rv32im_zkvm_ethereum_sha_v1)) {
    var bytes = @import("../../../frontends/riscv/runner/guest_precompile/test_elf.zig").buildReleaseProgram(tiny_code.len, &tiny_code, 256, .rv32im_zkvm_ethereum_sha_v1);
    const data_offset = std.mem.readInt(u32, bytes[88..92], .little);
    @memset(bytes[data_offset..][0..256], 0);
    const table = std.mem.readInt(u32, bytes[264..268], .little);
    for ([_]usize{ 2, 3, 7, 8, 9, 10, 11, 12 }, [_]u32{ 0x100100, 256, 0x100300, 0x100310, 0x100100, 0x100104, 0x100108, 0x100200 }) |index, value| std.mem.writeInt(u32, bytes[table + (index + 1) * 16 + 4 ..][0..4], value, .little);
    return bytes;
}
