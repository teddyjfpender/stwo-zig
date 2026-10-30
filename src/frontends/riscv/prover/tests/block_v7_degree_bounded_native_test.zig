//! Genuine opt-in original proofs. These are OPEN native sources; the test
//! does not claim full execution/provider or recursive-root qualification.
const std = @import("std");
const core = @import("stwo_core");
const Native = @import("../block_v7_native_proof_v1.zig");
const E = @import("../block_v7_execution_epoch_v1.zig");
const Support = @import("../block_v7_execution_test_support.zig");
const Source = @import("../block_v7_native_source_v1.zig");
const Fixed = @import("../../recursion/block_v7_native_fixed_profile_v1.zig");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Q = core.fields.qm31.QM31;
const Shape = @import("../../air/statement.zig").Blake3ExecutionStatement;
fn run(comptime access: bool) !void {
    const code = if (access) [_]u32{
        0x00700313, // x6=7
        0x00900393, // x7=9
        0x02730433, // mul x8,x6,x7
        0x001002b7, // x5=data base
        0x10028293, // x5+=256
        0x0082a023, // store product
        0x0002a483, // load x9
        0x0000006f,
    } else [_]u32{ 0x00700313, 0x00900393, 0x02730433, 0x0000006f };
    const elf = @import("../../runner/guest_precompile/test_elf.zig").buildReleaseProgram(code.len, &code, 512, .rv32im_zkvm_v1);
    const a = std.testing.allocator;
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config();
    var session = try @import("../../runner/mod.zig").BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var executed = try session.startSegment(code.len - 1);
    defer executed.deinit();
    try std.testing.expectEqual(@as(u32, 63), executed.exit_cpu.regs[8]);
    if (access) try std.testing.expectEqual(@as(u32, 63), executed.exit_cpu.regs[9]);
    var original_roots: [2][32]u8 = undefined;
    var original_access: [32]u8 = undefined;
    var original_shape: ?Shape = null;
    var original_claim_count: usize = 0;
    var original_events: u64 = 0;
    var original_entry: ?E.Entry = null;
    for ([_]Source.LayoutMode{ .canonical_v1, .degree_bounded_q2_v1 }) |mode| {
        var counters = try @import("../../air/lookups/tables/mod.zig").counter.Set.init(a);
        defer counters.deinit(a);
        var segment = try Support.Segment.init(a, &executed, config, @splat(7), 0, .rv32im_zkvm_v1, 0, &counters);
        var segment_live = true;
        defer if (segment_live) segment.deinit();
        // Retain only independent, narrow metadata before producer destruction.
        var statement = segment.pin.shape.*;
        var pin = segment.pin;
        pin.shape = &statement;
        pin.layout_mode = mode;
        var layout = try pin.layout(a);
        defer layout.deinit();
        const split: u32 = if (mode == .canonical_v1) 3 else 2;
        try std.testing.expectEqual(split, @import("../block_v5_native_projection_fused_proof_v2.zig").compositionSplit(layout.slots));
        const entries = [_]E.Entry{try pin.entry(a)};
        var counts: E.Counts = @splat(0);
        counts[@intFromEnum(E.Family.native)] = 1;
        const epoch = try E.Epoch.init(@splat(9), config, counts, &entries, entries.len);
        var proof = if (mode == .degree_bounded_q2_v1)
            try proveViaCheckpoint(a, &segment, &segment_live, pin, epoch, &entries)
        else
            try Native.For(Cpu).proveWithOptions(a, &segment.first, segment.owner, segment.source.inputs, pin, epoch, &entries, .{ .native_main_cache_bytes = 0 });
        defer proof.deinit(a);
        if (segment_live) segment.deinit();
        segment_live = false;
        try Support.roundTrip(a, &proof.stark);
        var captured = try Native.For(Cpu).verifyAndCapture(a, &proof, pin, epoch, &entries);
        defer captured.deinit();
        const open = captured.open;
        try std.testing.expect(open.state_residual.isZero());
        try std.testing.expect(open.register_residual.isZero());
        try std.testing.expect(open.ordinary_memory_residual.isZero());
        try std.testing.expect(open.auxiliary_clock_memory.isZero());
        try std.testing.expectEqual(@as(u64, code.len), open.fetch_count);
        // Independently reconstruct the recursive original equations/geometry
        // after all producer state is gone. This is not a recursive proof.
        const fixed = try Fixed.Owned.derive(a, pin, epoch, &entries, .{});
        defer fixed.deinit();
        try fixed.validate();
        try std.testing.expectEqual(mode, fixed.pin.layout_mode);
        try std.testing.expectEqual(split, fixed.shape.split);
        try std.testing.expectEqualDeep(layout.slots, fixed.projections);
        if (mode == .degree_bounded_q2_v1) try checkRecursiveSeam(a, fixed, &captured);
        if (mode == .canonical_v1) {
            original_roots = pin.roots;
            original_access = pin.access_root;
            original_shape = statement;
            original_claim_count = proof.claims.len;
            original_events = open.event_count;
            original_entry = entries[0];
            // The default branch is exactly the existing canonical identity.
            var default_pin = pin;
            default_pin.layout_mode = .canonical_v1;
            try std.testing.expectEqualDeep(entries[0], try default_pin.entry(a));
        } else {
            try std.testing.expectEqualDeep(original_roots, pin.roots);
            try std.testing.expectEqualDeep(original_access, pin.access_root);
            try std.testing.expectEqualDeep(original_shape.?, statement);
            try std.testing.expectEqual(original_claim_count + 2, proof.claims.len);
            try std.testing.expectEqual(original_events, open.event_count);
            try std.testing.expect(!std.meta.eql(original_entry.?.identity, entries[0].identity));
            var canonical_pin = pin;
            canonical_pin.layout_mode = .canonical_v1;
            if (Native.For(Cpu).verify(a, &proof, canonical_pin, epoch, &entries)) |_| return error.AcceptedWrongNativeLayoutMode else |_| {}
            // Mutate the two singleton claims which replace the same original
            // pair. Their aggregate remains unchanged, but both physical sums
            // are absorbed before the interaction root and must authenticate.
            var tested = false;
            for (layout.slots[0 .. layout.slots.len - 1], 0..) |slot, i| {
                if (slot.kind != .lookup or slot.kind.lookup.source != .opcode or slot.kind.lookup.source.opcode != .mul or slot.kind.lookup.partition != .range_check_8_11 or slot.kind.lookup.entries[0] != 9) continue;
                try std.testing.expectEqual(@as(u8, 1), slot.kind.lookup.entry_count);
                const before0 = proof.claims[i].sum;
                const before1 = proof.claims[i + 1].sum;
                proof.claims[i].sum = before0.add(Q.one());
                proof.claims[i + 1].sum = before1.sub(Q.one());
                try std.testing.expectEqualDeep(before0.add(before1), proof.claims[i].sum.add(proof.claims[i + 1].sum));
                if (Native.For(Cpu).verify(a, &proof, pin, epoch, &entries)) |_| return error.AcceptedCompensatedPhysicalClaims else |_| {}
                proof.claims[i].sum = before0;
                proof.claims[i + 1].sum = before1;
                tested = true;
                break;
            }
            try std.testing.expect(tested);
            _ = try Native.For(Cpu).verify(a, &proof, pin, epoch, &entries);
        }
    }
}
test "degree-bounded native MUL q3 control and q2 opt-in prove without access" {
    try run(false);
}
test "degree-bounded native MUL q3 control and q2 opt-in prove with access" {
    try run(true);
}

/// The independently selected roster must drive both recursive equations and
/// exact cold/live transcript framing, including every expanded physical sum.
fn checkRecursiveSeam(a: std.mem.Allocator, profile: *const Fixed.Owned, captured: *const Native.VerifiedCapture) !void {
    const Composition = @import("../../recursion/air/block_v7_native_composition_v1.zig");
    var compiled = try Composition.compile(a, profile);
    defer compiled.deinit();
    try compiled.validateAgainst(profile);
    const public = try Composition.publicInputs(a, profile, captured.claims, captured.memory_claims);
    defer a.free(public);
    const drawn = try profile.epoch.draw(a);
    var challenges: [106]Q = undefined;
    for (drawn.word.universal_prefix.elements, 0..) |element, i| {
        challenges[2 * i] = element.z;
        challenges[2 * i + 1] = element.alpha;
    }
    inline for (.{ drawn.word.transition, drawn.word.link, drawn.word.initial, drawn.word.endpoint, drawn.word.range16 }, 0..) |element, i| {
        challenges[94 + 2 * i] = element.z;
        challenges[95 + 2 * i] = element.alpha;
    }
    challenges[104] = drawn.memory.interval.z;
    challenges[105] = drawn.memory.interval.powers[1];
    var live = try @import("../../recursion/air/block_v7_native_transcript_v1.zig").planReplay(a, profile, captured, 8);
    defer live.deinit();
    var cold = try @import("../../recursion/block_v7_native_fixed_transcript_v1.zig").derive(a, profile, captured.claims, captured.memory_claims, 8, .{});
    defer cold.deinit();
    try std.testing.expectEqualDeep(live.plan.id, cold.id);
    const inputs = try a.alloc(Q, compiled.sources.len);
    defer a.free(inputs);
    for (compiled.sources, inputs) |source, *value| value.* = switch (source) {
        .sample => |i| captured.proof.sampled_values[i],
        .challenge => |i| challenges[i],
        .public_input => |i| public[i],
        .composition => captured.proof.composition_randomness,
        .oods => captured.proof.oods_seed,
        else => return error.UnexpectedNativeCompositionSource,
    };
    const values = try a.alloc(Q, compiled.circuit.nodes.len);
    defer a.free(values);
    try compiled.circuit.evaluateInto(inputs, values);
    var checked: usize = 0;
    for (compiled.sources, inputs) |source, *value| {
        if (source != .public_input or source.public_input < 8 or source.public_input >= 8 + profile.projections.len) continue;
        const before = value.*;
        value.* = before.add(Q.one());
        try std.testing.expectError(error.UnsatisfiedCircuit, compiled.circuit.evaluateInto(inputs, values));
        value.* = before;
        checked += 1;
    }
    try std.testing.expectEqual(profile.projections.len, checked);
    try compiled.circuit.evaluateInto(inputs, values);
}

fn proveViaCheckpoint(a: std.mem.Allocator, segment: *Support.Segment, live: *bool, pin: Native.Pin, epoch: E.Epoch, entries: []const E.Entry) !Native.Proof {
    const Cache = @import("../block_v7_native_checkpoint_v1.zig");
    const Event = @import("../../air/block/memory_transition.zig").Transition;
    const Sink = struct {
        count: usize = 0,
        fn put(context: *anyopaque, _: Event) !void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.count += 1;
        }
    };
    var sink = Sink{};
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var counters = try @import("../../air/lookups/tables/mod.zig").counter.Set.init(a);
    defer counters.deinit(a);
    const names = Cache.Names{ .raw = "native.raw", .native = "native.pcs", .access = "access.pcs" };
    const limits = Cache.Limits{
        .native_layout_mode = pin.layout_mode,
        .columns = .{ .columns = .{ .max_columns = 4096, .max_log_size = 20, .max_file_bytes = 1 << 28, .max_loaded_bytes = 1 << 28 }, .max_public_words = 0, .max_public_bytes = 0 },
        .pcs = .{ .max_columns = 4096, .max_log_size = 20, .max_file_bytes = 1 << 28, .max_loaded_bytes = 1 << 28 },
        .source = .{ .max_slots = 100, .max_witness_cells = 1 << 20, .max_metadata_bytes = 1 << 20, .register_custody_mode = 1 },
        .max_total_bytes = 1 << 29,
    };
    var record = try Cache.collect(a, temporary.dir, names, segment.owner, epoch.config, .rv32im_zkvm_v1, pin.index, pin.frame.global_first_cycle, &counters, .{ .context = &sink, .put = Sink.put }, limits);
    defer record.deinit();
    try std.testing.expectEqual(pin.layout_mode, record.pin().layout_mode);
    try std.testing.expectEqualDeep(try pin.entry(a), try record.entry(a));
    try std.testing.expectEqual(pin.expected_events, sink.count);
    segment.deinit();
    live.* = false;
    var wrong = limits;
    wrong.native_layout_mode = .canonical_v1;
    try std.testing.expectError(error.InvalidV7CheckpointLayoutMode, Cache.load(a, temporary.dir, names, &record, wrong));
    record.layout_mode = .canonical_v1;
    try std.testing.expectError(error.InvalidV7CheckpointLayoutMode, Cache.load(a, temporary.dir, names, &record, limits));
    record.layout_mode = pin.layout_mode;
    return Cache.proveOneWithOptions(a, temporary.dir, names, &record, limits, epoch, entries, .{ .native_main_cache_bytes = 0 });
}
