//! Nonproving public-authority, equations, source-link and API qualification.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const P = core.fields.packed_qm31.PackedQM31;
const Plan = @import("block_v5_readonly_input_plan_v1.zig");
const Protocol = @import("block_v5_readonly_input_protocol_v1.zig");
const Air = @import("block_v5_readonly_input_component_v1.zig");
const Proof = @import("block_v5_readonly_input_proof_v1.zig");
const Receiver = @import("block_v5_readonly_input_receiver_v1.zig");
const Sources = @import("block_v5_initial_sources_v1.zig");
const Frame = @import("../recursion/air/framework_interaction.zig");
const base: u32 = 0x800000;
const input = [_]u8{ 255, 255, 255, 255, 255, 254, 253 };
fn sourcePins() !Sources.Pins {
    const tree = @import("../air/memory_commitment/blake3_state_tree.zig");
    const leaves = [_]tree.Leaf{ .{ .index = base / 4, .value = 0xffffffff }, .{ .index = base / 4 + 1, .value = 0x00fdfeff } };
    var words: [2 * Sources.INPUT_RECORD_BYTES]u8 = undefined;
    inline for (0..2) |i| {
        std.mem.writeInt(u32, words[i * 8 ..][0..4], base + i * 4, .little);
        std.mem.writeInt(u32, words[i * 8 + 4 ..][0..4], leaves[i].value, .little);
    }
    var touches: [3 * Sources.TOUCH_RECORD_BYTES]u8 = undefined;
    inline for (0..3) |i| {
        touches[i * 9] = 1;
        std.mem.writeInt(u32, touches[i * 9 + 1 ..][0..4], base + i * 4, .little);
        std.mem.writeInt(u32, touches[i * 9 + 5 ..][0..4], if (i < 2) leaves[i].value else 0, .little);
    }
    return .{
        .layout = .{ .program_base = 0x1000, .program_end = 0x2000, .data_base = base, .data_end = base + 4096, .stack_bottom = 0, .stack_top = 0, .io_base = 0, .io_end = 0, .input_base = base, .input_end = base + 16, .output_len_addr = base + 32, .output_data_addr = base + 36, .output_base = base + 32, .output_end = base + 128 },
        .initial_rw_root = (try tree.TreeHasher.init(.memory).root(&leaves)).bytes,
        .initial_registers = @splat(0),
        .public_input_sha256 = Sources.sha256(&input),
        .public_input_len = input.len,
        .input_words = .{ .sha256 = Sources.sha256(&words), .records = 2 },
        .rw_words = .{ .sha256 = Sources.sha256(&.{}), .records = 0 },
        .first_touches = .{ .sha256 = Sources.sha256(&touches), .records = 3 },
    };
}
const selected = [_]u32{ base, base + 8 };
fn proposed(plan: Plan.Owned) !Proof.Pin {
    return .{ .plan_digest = plan.digest, .source_identity = @splat(8), .events = 3, .row_log = 3, .roots = .{ @splat(5), @splat(6) }, .config = .{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) } };
}
fn challenges() Protocol.Challenges {
    const Elements = @import("../air/relation_challenges.zig").RelationElements;
    return .{
        .word = undefined,
        .classification = Elements(5).init(Q.fromU32Unchecked(9, 2, 3, 7), Q.fromU32Unchecked(3, 4, 5, 6)),
        .read = Elements(4).init(Q.fromU32Unchecked(8, 5, 7, 3), Q.fromU32Unchecked(7, 4, 8, 6)),
    };
}
fn exactChallenges() Protocol.Challenges {
    var result = challenges();
    result.word.transition = @import("../air/relation_challenges.zig").RelationElements(11).init(Q.fromU32Unchecked(11, 7, 13, 17), Q.fromU32Unchecked(19, 23, 29, 31));
    return result;
}
fn events() [3]@import("../air/block/memory_transition.zig").Transition {
    return .{
        .{ .space = 1, .address = base, .clock = (@as(u64, 1) << 48) + 5, .before = 0xffffffff, .after = 0xffffffff },
        // The partial input word remains writable because it is unselected.
        .{ .space = 1, .address = base + 4, .clock = (@as(u64, 1) << 32) + 7, .before = 0x00fdfeff, .after = 5 },
        .{ .space = 1, .address = base + 8, .clock = (@as(u64, 1) << 63) + 9, .before = 0, .after = 0 },
    };
}
fn secure(columns: [20]@import("stwo_prover_engine").pcs.ColumnEvaluation, physical: usize) [20]Q {
    var result: [20]Q = undefined;
    for (&result, columns) |*value, column| value.* = Q.fromBase(column.values[physical]);
    return result;
}
fn allEquations(trace: *const Proof.Trace, generated: *const Proof.Generated, pin: Proof.Pin, relations: *const Protocol.Challenges) !bool {
    const spec = Air.Spec{ .claim = generated.claim, .challenges = relations };
    const size: usize = @as(usize, 1) << @intCast(pin.row_log);
    for (0..size) |logical| {
        const physical = Frame.committedRow(logical, pin.row_log);
        const previous = Frame.committedRow((logical + size - 1) % size, pin.row_log);
        var row: [Air.Layout.len]Q = undefined;
        for (&row, trace.main) |*value, column| value.* = Q.fromBase(column.values[physical]);
        const equations = try spec.evaluate(.{Q.fromBase(trace.fixed[0].values[physical])}, row, @splat(Q.zero()), secure(generated.columns, physical), secure(generated.columns, previous), @intCast(size));
        for (equations) |equation| if (!equation.isZero()) return false;
    }
    return true;
}
test "block-v5 readonly input public values subset complement and authority reject relabeling" {
    const a = std.testing.allocator;
    const pins = try sourcePins();
    var plan = try Plan.derive(a, pins, &input, &selected, .{});
    defer plan.deinit();
    var public = try Plan.admit(a, .{ .source = pins, .addresses = &selected, .expected_digest = plan.digest }, &input);
    defer public.deinit();
    try std.testing.expectEqual(@as(u32, 0), plan.intervals[0].lower);
    try std.testing.expectEqual(Plan.WORD_LIMIT, plan.intervals[plan.intervals.len - 1].upper);
    for (plan.intervals[1..], 0..) |interval, i| try std.testing.expectEqual(plan.intervals[i].upper, interval.lower);
    try std.testing.expectEqual(@as(u32, 0xffffffff), plan.intervals[try plan.find(base)].value);
    try std.testing.expectEqual(@as(u32, 0), plan.intervals[try plan.find(base + 8)].value);
    try std.testing.expect(!plan.intervals[try plan.find(base + 4)].readonly);
    try std.testing.expectEqual(@as(u32, 0x00fdfeff), try Sources.inputWord(pins, &input, base + 4));
    try std.testing.expectError(error.InvalidReadonlyInputAddressRoster, Plan.derive(a, pins, &input, &.{ base, base }, .{}));
    try std.testing.expectError(error.InvalidReadonlyInputAddressRoster, Plan.derive(a, pins, &input, &.{base + 1}, .{}));
    try std.testing.expectError(error.InvalidReadonlyInputAddressRoster, Plan.derive(a, pins, &input, &.{base + 16}, .{}));
    try std.testing.expectError(error.ReadonlyInputPlanResourceLimit, Plan.derive(a, pins, &input, &selected, .{ .max_words = 1 }));
    var corrupt = input;
    corrupt[0] ^= 1;
    try std.testing.expectError(error.UntrustedReadonlyInputBytes, Plan.admit(a, .{ .source = pins, .addresses = &selected, .expected_digest = plan.digest }, &corrupt));
    try std.testing.expectError(error.UntrustedReadonlyInputPlan, Plan.admit(a, .{ .source = pins, .addresses = &selected, .expected_digest = @splat(1) }, &input));
    try std.testing.expectError(error.UntrustedReadonlyInputPlan, Plan.admit(a, .{ .source = pins, .addresses = &.{base + 8}, .expected_digest = plan.digest }, &input));
    var changed_authority = pins;
    changed_authority.initial_rw_root[0] ^= 1;
    try std.testing.expectError(error.UntrustedReadonlyInputPlan, Plan.admit(a, .{ .source = changed_authority, .addresses = &selected, .expected_digest = plan.digest }, &input));
    var fallback = try Plan.derive(a, pins, &input, &.{}, .{});
    defer fallback.deinit();
    try std.testing.expectEqual(@as(usize, 1), fallback.intervals.len);
    try std.testing.expect(!fallback.intervals[0].readonly);
    _ = try Air.witnessRow(events()[1], fallback.intervals[0]);
}
test "block-v5 readonly input source census scalar equations and coherent forgeries reject" {
    const a = std.testing.allocator;
    var plan = try Plan.derive(a, try sourcePins(), &input, &selected, .{});
    defer plan.deinit();
    const pin = try proposed(plan);
    const relations = exactChallenges();
    var trace = try Proof.Trace.init(a, plan, &events(), pin);
    defer trace.deinit(a);
    var generated = try Proof.generateInteraction(a, &trace, pin, &relations);
    defer generated.deinit(a);
    try std.testing.expect(try allEquations(&trace, &generated, pin, &relations));
    try Proof.checkProviders(plan, pin, generated.claim, trace.counters, &relations);
    try std.testing.expectEqual(@as(u64, 2), generated.claim.readonly_count);
    var source_sum = Q.zero();
    for (events()) |event| source_sum = source_sum.add(try relations.word.transition.combineBase(@import("block_v5_word_memory_protocol_v1.zig").transitionTuple(event)).inv());
    const partition = Proof.Open{ .claim = generated.claim, .mutable_events = 1, .source_identity = pin.source_identity, .plan_digest = plan.digest, .sealed_digest = @splat(2) };
    try Receiver.checkSourceEquation(partition, source_sum, 3, pin);
    try std.testing.expectError(error.UnclosedReadonlyInputSource, Receiver.checkSourceEquation(partition, source_sum.add(Q.one()), 3, pin));
    try std.testing.expectError(error.UnclosedReadonlyInputSource, Receiver.checkSourceEquation(partition, source_sum, 2, pin));
    trace.counters[0] += 1;
    try std.testing.expectError(error.InvalidReadonlyInputProviderCensus, Proof.checkProviders(plan, pin, generated.claim, trace.counters, &relations));
    trace.counters[0] -= 1;
    const physical = Frame.committedRow(0, pin.row_log);
    // A selected address cannot claim the mutable interval or escape the
    // input value with a coherent regenerated interaction polynomial.
    trace.mainValues(Air.Layout.interval + 2)[physical] = M.zero();
    var forged = try Proof.generateInteraction(a, &trace, pin, &relations);
    defer forged.deinit(a);
    try std.testing.expectError(error.InvalidReadonlyInputProviderCensus, Proof.checkProviders(plan, pin, forged.claim, trace.counters, &relations));
    trace.mainValues(Air.Layout.interval + 2)[physical] = M.one();
    trace.mainValues(Air.Layout.after + 1)[physical] = M.zero();
    try std.testing.expect(!try allEquations(&trace, &generated, pin, &relations));
    trace.mainValues(Air.Layout.after + 1)[physical] = M.fromCanonical(65535);
    trace.mainValues(Air.Layout.lower_gap_bits)[physical] = M.one();
    try std.testing.expect(!try allEquations(&trace, &generated, pin, &relations));
    trace.mainValues(Air.Layout.lower_gap_bits)[physical] = M.zero();
    trace.mainValues(Air.Layout.upper_gap_bits)[physical] = M.one();
    try std.testing.expect(!try allEquations(&trace, &generated, pin, &relations));
    trace.mainValues(Air.Layout.upper_gap_bits)[physical] = M.zero();
    // Coherent new high clock limbs still satisfy classification equations,
    // but the exact original source multiset rejects their substitution.
    trace.mainValues(Air.Layout.clock + 3)[physical] = M.fromCanonical(2);
    var clock_forgery = try Proof.generateInteraction(a, &trace, pin, &relations);
    defer clock_forgery.deinit(a);
    try std.testing.expect(try allEquations(&trace, &clock_forgery, pin, &relations));
    try Proof.checkProviders(plan, pin, clock_forgery.claim, trace.counters, &relations);
    const forged_partition = Proof.Open{ .claim = clock_forgery.claim, .mutable_events = 1, .source_identity = pin.source_identity, .plan_digest = plan.digest, .sealed_digest = @splat(2) };
    try std.testing.expectError(error.UnclosedReadonlyInputSource, Receiver.checkSourceEquation(forged_partition, source_sum, 3, pin));
    trace.mainValues(Air.Layout.clock + 3)[physical] = M.one();
    const padded = Frame.committedRow(3, pin.row_log);
    trace.mainValues(Air.Layout.word_bits)[padded] = M.one();
    try std.testing.expect(!try allEquations(&trace, &generated, pin, &relations));
    var changed = events()[0];
    changed.after -= 1;
    try std.testing.expectError(error.InvalidReadonlyInputClassification, Air.witnessRow(changed, plan.intervals[try plan.find(base)]));
    changed = events()[0];
    changed.space = 0;
    try std.testing.expectError(error.InvalidReadonlyInputSourceEvent, Air.witnessRow(changed, plan.intervals[try plan.find(base)]));
    try std.testing.expectError(error.InvalidReadonlyInputClassification, Air.witnessRow(events()[1], plan.intervals[try plan.find(base)]));
    const native_identity = Proof.sourceIdentity(.native, 0, @splat(3), @splat(4), .{ @splat(5), @splat(6) }, @splat(7));
    const caller_identity = Proof.sourceIdentity(.caller, 0, @splat(3), @splat(4), .{ @splat(5), @splat(6) }, @splat(7));
    try std.testing.expect(!std.meta.eql(native_identity, caller_identity));
}
fn allocationLifecycle(a: std.mem.Allocator) !void {
    var plan = try Plan.derive(a, try sourcePins(), &input, &selected, .{});
    defer plan.deinit();
    const pin = try proposed(plan);
    var trace = try Proof.Trace.init(a, plan, &events(), pin);
    defer trace.deinit(a);
    const relations = exactChallenges();
    var generated = try Proof.generateInteraction(a, &trace, pin, &relations);
    defer generated.deinit(a);
    try Proof.checkProviders(plan, pin, generated.claim, trace.counters, &relations);
    try std.testing.expect(try allEquations(&trace, &generated, pin, &relations));
}
test "block-v5 readonly input collection cleanup survives every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationLifecycle, .{});
}
test "block-v5 readonly input geometry resource and immutable matrix borrows reject substitution" {
    const a = std.testing.allocator;
    var plan = try Plan.derive(a, try sourcePins(), &input, &selected, .{});
    defer plan.deinit();
    const pin = try proposed(plan);
    var invalid = pin;
    invalid.events = 9;
    try std.testing.expectError(error.InvalidReadonlyInputProofGeometry, invalid.validate());
    invalid = pin;
    invalid.limits.max_matrix_bytes = 1;
    try std.testing.expectError(error.ReadonlyInputProofResourceLimit, invalid.validate());
    var trace = try Proof.Trace.init(a, plan, &events(), pin);
    defer trace.deinit(a);
    trace.main[0].values = trace.main[1].values;
    try std.testing.expectError(error.UntrustedReadonlyInputTrace, trace.require(pin));
}
test "block-v5 readonly input all mutable and all readonly partitions preserve exact census" {
    const a = std.testing.allocator;
    const relations = exactChallenges();
    var fallback = try Plan.derive(a, try sourcePins(), &input, &.{}, .{});
    defer fallback.deinit();
    const fallback_pin = try proposed(fallback);
    var writable_trace = try Proof.Trace.init(a, fallback, &events(), fallback_pin);
    defer writable_trace.deinit(a);
    var writable = try Proof.generateInteraction(a, &writable_trace, fallback_pin, &relations);
    defer writable.deinit(a);
    try Proof.checkProviders(fallback, fallback_pin, writable.claim, writable_trace.counters, &relations);
    try std.testing.expect(try allEquations(&writable_trace, &writable, fallback_pin, &relations));
    try std.testing.expectEqual(@as(u64, 0), writable.claim.readonly_count);
    try std.testing.expect(writable.claim.source_sum.add(writable.claim.mutable_sum).isZero());
    var plan = try Plan.derive(a, try sourcePins(), &input, &selected, .{});
    defer plan.deinit();
    const pin = try proposed(plan);
    var readonly_events = events();
    readonly_events[1].address = base;
    readonly_events[1].before = 0xffffffff;
    readonly_events[1].after = 0xffffffff;
    var readonly_trace = try Proof.Trace.init(a, plan, &readonly_events, pin);
    defer readonly_trace.deinit(a);
    var readonly = try Proof.generateInteraction(a, &readonly_trace, pin, &relations);
    defer readonly.deinit(a);
    try Proof.checkProviders(plan, pin, readonly.claim, readonly_trace.counters, &relations);
    try std.testing.expect(try allEquations(&readonly_trace, &readonly, pin, &relations));
    try std.testing.expectEqual(@as(u64, 3), readonly.claim.readonly_count);
    try std.testing.expect(readonly.claim.mutable_sum.isZero());
    var malformed = readonly.claim;
    // Corrupt the raw wire limb after constructing a valid claim. Field
    // constructors require canonical inputs and cannot model malformed wire.
    malformed.source_sum.c0.a.v = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidReadonlyInputClaim, Proof.checkProviders(plan, pin, malformed, readonly_trace.counters, &relations));
}
test "block-v5 readonly input arbitrary OODS SIMD masks preserve all source equations" {
    const relations = exactChallenges();
    const claim = Protocol.Claim{ .source_sum = Q.one(), .mutable_sum = Q.zero(), .classification_sum = Q.one(), .read_sum = Q.zero(), .readonly_count = 1 };
    const spec = Air.Spec{ .claim = claim, .challenges = &relations };
    var domain = try spec.prepareDomain(8);
    var row: [Air.Layout.len]Q = undefined;
    var current: [20]Q = undefined;
    var previous: [20]Q = undefined;
    for (&row, 0..) |*value, i| value.* = Q.fromU32Unchecked(@intCast(i + 1), 2, 3, 4);
    for (&current, &previous, 0..) |*value, *old, i| {
        value.* = Q.fromU32Unchecked(7, @intCast(i), 11, 13);
        old.* = Q.fromU32Unchecked(17, 19, @intCast(i), 23);
    }
    const active = Q.fromU32Unchecked(2, 3, 5, 7);
    const scalar = try domain.evaluate(.{active}, row, @splat(Q.zero()), current, previous, 8);
    var packed_row: [Air.Layout.len]P = undefined;
    var packed_current: [20]P = undefined;
    var packed_previous: [20]P = undefined;
    for (&packed_row, row) |*value, cell| value.* = P.splat(cell);
    for (&packed_current, &packed_previous, current, previous) |*value, *old, cell, prior| {
        value.* = P.splat(cell);
        old.* = P.splat(prior);
    }
    const packed_result = domain.evaluatePacked(.{P.splat(active)}, packed_row, @splat(P.zero()), packed_current, packed_previous);
    for (scalar, packed_result) |expected, found| for (0..core.fields.m31.PACK_WIDTH) |lane| try std.testing.expect(expected.eql(found.lane(lane)));
    const component = Air.Component{ .spec = spec, .log_size = 3 };
    var mask = try component.maskPoints(std.testing.allocator, .{ .x = Q.one(), .y = Q.zero() }, 3);
    defer mask.deinitDeep(std.testing.allocator);
    for (mask.items[1]) |points| try std.testing.expectEqual(@as(usize, 1), points.len);
    for (mask.items[2]) |points| try std.testing.expectEqual(@as(usize, 2), points.len);
    try std.testing.expectEqual(@as(u8, 3), try component.constraintDegreeBound(204));
}
test "block-v5 readonly input producer fresh native caller receiver bodies compile without invocation" {
    const Api = Proof.ForBackend(Cpu);
    const Fresh = Receiver.ForBackend(Cpu);
    inline for (.{ &Api.commit, &Api.prove, &Api.verifyOwned, &Fresh.verifyNativeOwned, &Fresh.verifyCallerOwned }) |function| std.mem.doNotOptimizeAway(function);
}
