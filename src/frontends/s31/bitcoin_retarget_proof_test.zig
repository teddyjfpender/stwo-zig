//! Opt-in native proof of Bitcoin mainnet's height-2016 retarget arithmetic.
//! This proves the transition relation only. The chain fold still stops before
//! height 2016, so no recursive proof currently authenticates this input time.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cpu = @import("stwo_circuit_cpu_integration");
const retarget = @import("bitcoin_retarget.zig");
const native = @import("native_verifier.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Var = circuit.builder.Var;
const NoValue = circuit.builder.NoValue;

fn packedConstant(comptime V: type, ctx: *circuit.builder.Context(V), word: u32) !Var {
    return ctx.constant(QM31.fromU32Unchecked(word & 0xffff, word >> 16, 0, 0));
}

fn hint(comptime V: type, value: u32) V {
    return circuit.builder.ivalue.fromQm31(V, QM31.fromBase(M31.fromCanonical(value)));
}

fn publicWords(last_time: u32, bits: u32) [8]u32 {
    return .{
        bits & 0xffff,
        bits >> 16,
        last_time,
        2016,
        retarget.genesis_time,
        0x1d00ffff,
        retarget.target_timespan,
        1, // Mainnet first-retarget relation version.
    };
}

fn build(comptime V: type, allocator: std.mem.Allocator, last_time: u32, claimed_bits: u32) !circuit.builder.Context(V) {
    var ctx = try circuit.builder.Context(V).init(allocator, circuit.common.component_list.N_RESERVED);
    errdefer ctx.deinit();
    const last = try circuit.builder.wrappers.guessU32(V, &ctx, circuit.builder.wrappers.u32Value(V, last_time));
    const claimed = [2]Var{
        try ctx.guessU16(hint(V, claimed_bits & 0xffff)),
        try ctx.guessU16(hint(V, claimed_bits >> 16)),
    };
    const bits = try retarget.constrainFirstMainnetRetarget(V, &ctx, last, claimed);
    const output: [8]Var = .{
        bits[0],
        bits[1],
        last.get(),
        try packedConstant(V, &ctx, 2016),
        try packedConstant(V, &ctx, retarget.genesis_time),
        try packedConstant(V, &ctx, 0x1d00ffff),
        try packedConstant(V, &ctx, retarget.target_timespan),
        try packedConstant(V, &ctx, 1),
    };
    try ctx.setOutputs(&output);
    try ctx.finalize(false);
    try circuit.common.finalize.padContext(V, &ctx);
    return ctx;
}

test "first-retarget relation has one value-free topology at clamp and compact boundaries" {
    const allocator = std.testing.allocator;
    var topology = try build(NoValue, allocator, 0, 0);
    defer topology.deinit();
    var pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &topology.circuit);
    defer pp.deinit(allocator);
    const layout = pp.layout();
    const pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(
        try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 4),
        layout.traceLogSize(),
    );
    const root = try pp.preprocessedRoot(allocator, pcs.fri_config.log_blowup_factor);

    for ([_]u32{
        0,
        retarget.genesis_time + retarget.min_timespan - 1,
        retarget.genesis_time + retarget.min_timespan,
        retarget.genesis_time + retarget.min_timespan + 1,
        retarget.genesis_time + 604809,
        retarget.genesis_time + 604810,
        retarget.genesis_time + retarget.target_timespan - 1,
        retarget.genesis_time + retarget.target_timespan,
        retarget.genesis_time + retarget.max_timespan,
        0xffffffff,
    }) |last| {
        const expected = retarget.hostFirstRetargetBits(last);
        var honest = try build(QM31, allocator, last, expected);
        defer honest.deinit();
        try std.testing.expect(try honest.isCircuitValid());
        var honest_pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &honest.circuit);
        defer honest_pp.deinit(allocator);
        try std.testing.expect(honest_pp.layout().eql(&layout));
        const honest_root = try honest_pp.preprocessedRoot(allocator, pcs.fri_config.log_blowup_factor);
        try std.testing.expectEqualDeep(root, honest_root);
        for ([_]u32{ expected ^ 1, expected ^ 0x01000000 }) |bad_bits| {
            var false_claim = try build(QM31, allocator, last, bad_bits);
            defer false_claim.deinit();
            try std.testing.expect(!(try false_claim.isCircuitValid()));
        }
    }
}

test "first-retarget native proofs bind public bits and timestamp across boundary cases" {
    const allocator = std.heap.page_allocator;
    var bundle = try cpu.air.parse(allocator, @embedFile("s31_air_programs"));
    defer bundle.deinit();
    var topology = try build(NoValue, allocator, 0, 0);
    defer topology.deinit();
    var pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &topology.circuit);
    defer pp.deinit(allocator);
    const layout = pp.layout();
    const pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(
        try core.pcs.config_v2.FriConfigV2.init(26, 0, 1, 70, 4),
        layout.traceLogSize(),
    );
    const root = try pp.preprocessedRoot(allocator, pcs.fri_config.log_blowup_factor);
    const hash = try circuit.common.circuit_hash.hostCircuitHash(
        try circuit.common.component_list.circuitComponentLogSizes(&layout),
        pcs.fri_config.log_blowup_factor,
        root,
    );

    // Cover signed pre-genesis time, compact sign-bit normalization, and the
    // upper timespan clamp with the same value-free verification root.
    for ([_]u32{ 0, retarget.genesis_time + 604810, 0xffffffff }) |last| {
        const bits = retarget.hostFirstRetargetBits(last);
        const expected = publicWords(last, bits);
        var values = try build(QM31, allocator, last, bits);
        defer values.deinit();
        try std.testing.expect(try values.isCircuitValid());
        var value_pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(allocator, &values.circuit);
        defer value_pp.deinit(allocator);
        try std.testing.expectEqualDeep(root, try value_pp.preprocessedRoot(allocator, pcs.fri_config.log_blowup_factor));
        values.circuit.deinit(allocator);
        values.circuit = .{};

        var timer = try std.time.Timer.start();
        var proof = try cpu.Internal.prove(allocator, values.values(), &pp, &bundle, pcs, .{ .evaluations_only = true }, {});
        defer proof.deinit();
        const prove_ns = timer.read();
        try std.testing.expectEqual(@as(usize, 8), proof.output_values.len);
        for (proof.output_values, expected) |value, word|
            try std.testing.expectEqual(word, circuit.builder.ivalue.unpackU32(QM31, value));
        const bytes = try native.serialize(allocator, &proof);
        defer allocator.free(bytes);
        try native.verify(allocator, &layout, &bundle, pcs, root, hash, expected, bytes);

        var changed = expected;
        changed[0] ^= 1;
        if (native.verify(allocator, &layout, &bundle, pcs, root, hash, changed, bytes)) |_|
            return error.AcceptedAlteredRetargetMantissa
        else |_| {}
        changed = expected;
        changed[1] ^= 0x0100;
        if (native.verify(allocator, &layout, &bundle, pcs, root, hash, changed, bytes)) |_|
            return error.AcceptedAlteredRetargetExponent
        else |_| {}
        changed = expected;
        changed[2] ^= 1;
        if (native.verify(allocator, &layout, &bundle, pcs, root, hash, changed, bytes)) |_|
            return error.AcceptedAlteredRetargetTimestamp
        else |_| {}

        std.debug.print("Bitcoin first-retarget relation: last={d} bits=0x{x:0>8} proof_bytes={d} prove_seconds={d:.3} root={s}\n", .{
            last,
            bits,
            bytes.len,
            @as(f64, @floatFromInt(prove_ns)) / std.time.ns_per_s,
            &std.fmt.bytesToHex(root, .lower),
        });
    }
}
