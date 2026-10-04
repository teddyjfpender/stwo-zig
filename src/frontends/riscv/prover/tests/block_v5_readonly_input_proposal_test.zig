//! Real bounded PCS commitments and candidate late binding, never a STARK,
//! guest execution or verified native/caller/complete receipt.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const M = core.fields.m31.M31;
const Selection = @import("../block_v5_readonly_input_selection_v1.zig");
const Proposal = @import("../block_v5_readonly_input_proposal_v1.zig");
const Classification = @import("../block_v5_readonly_input_proof_v1.zig");
const Plan = @import("../block_v5_readonly_input_plan_v1.zig");
const Sources = @import("../block_v5_initial_sources_v1.zig");
const Transition = @import("../../air/block/memory_transition.zig").Transition;
const base: u32 = 0x900000;
const input = [_]u8{ 7, 0, 0, 0, 9, 8, 7 };
const addresses = [_]u32{ base, base + 8 };
fn sources() !Sources.Pins {
    const Tree = @import("../../air/memory_commitment/blake3_state_tree.zig");
    const leaves = [_]Tree.Leaf{ .{ .index = base / 4, .value = 7 }, .{ .index = base / 4 + 1, .value = 0x070809 } };
    var words: [16]u8 = undefined;
    inline for (0..2) |i| {
        std.mem.writeInt(u32, words[i * 8 ..][0..4], base + i * 4, .little);
        std.mem.writeInt(u32, words[i * 8 + 4 ..][0..4], leaves[i].value, .little);
    }
    // Final source file describes only the candidate mutable first touch.
    // Full initial input roster/root still include every original word.
    var touch: [9]u8 = undefined;
    touch[0] = 1;
    std.mem.writeInt(u32, touch[1..5], base + 4, .little);
    std.mem.writeInt(u32, touch[5..9], 0x070809, .little);
    return .{ .layout = .{ .program_base = 0x1000, .program_end = 0x2000, .data_base = base, .data_end = base + 4096, .stack_bottom = 0, .stack_top = 0, .io_base = 0, .io_end = 0, .input_base = base, .input_end = base + 16, .output_len_addr = base + 32, .output_data_addr = base + 36, .output_base = base + 32, .output_end = base + 128 }, .initial_rw_root = (try Tree.TreeHasher.init(.memory).root(&leaves)).bytes, .initial_registers = @splat(0), .public_input_sha256 = Sources.sha256(&input), .public_input_len = input.len, .input_words = .{ .sha256 = Sources.sha256(&words), .records = 2 }, .rw_words = .{ .sha256 = Sources.sha256(&.{}), .records = 0 }, .first_touches = .{ .sha256 = Sources.sha256(&touch), .records = 1 } };
}
fn pins(selection: *const Selection.Owned) Selection.Pins {
    return .{ .authority = selection.authority, .addresses = selection.addresses, .expected_digest = selection.digest, .limits = selection.limits };
}
fn events() [3]Transition {
    // Global clocks exceed u32 and retain all bits through both passes.
    const first = @as(u64, 1) << 34;
    return .{ .{ .space = 1, .address = base, .clock = first + 1, .before = 7, .after = 7 }, .{ .space = 1, .address = base + 4, .clock = first + 5, .before = 0x070809, .after = 5 }, .{ .space = 1, .address = base + 8, .clock = first + 9, .before = 0, .after = 0 } };
}
fn sourcePin() !Proposal.SourcePin {
    return .{ .kind = .native, .index = 0, .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = (@as(u64, 1) << 32) + 1, .cycle_count = 3 }, .roots = .{ @splat(3), @splat(4) }, .access_root = @splat(5), .roster_digest = Sources.sha256("bounded-actual-source-roster"), .all_rw_events = 3, .row_log = 3, .config = .{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) } };
}
fn inspectedProposal(source: Proposal.SourcePin, selection: *const Selection.Owned, inspected: Proposal.Inspected) Proposal.Proposal {
    // Candidate independently pinned metadata for pure binding fixtures; this
    // creates no STARK or accepted source receipt. Real roots are tested below.
    return .{ .expected = .{ .source = source, .selection_digest = selection.digest, .classifier_roots = if (source.all_rw_events == 0) null else .{ @splat(6), @splat(7) }, .census = inspected.census, .counter_digest = inspected.counter_digest, .event_digest = inspected.event_digest, .limits = .{} } };
}
test "block-v5 readonly proposal shares immutable selection and actual late source derivation" {
    const a = std.testing.allocator;
    const actual = try sources();
    const authority = try Selection.Authority.fromSources(actual);
    var selection = try Selection.derive(a, authority, &input, &addresses, .{});
    defer selection.deinit();
    try selection.require(pins(&selection), &input);
    var final = try Plan.derive(a, actual, &input, &addresses, .{});
    defer final.deinit();
    try std.testing.expectEqual(selection.intervals.len, final.intervals.len);
    for (selection.intervals, final.intervals) |early, late| try std.testing.expectEqualDeep(early, late);
    try std.testing.expectEqual(@as(u32, 0), selection.intervals[try selection.find(base + 8)].value);
    try std.testing.expectEqual(@as(u32, 0x070809), try Sources.inputWordAt(actual.layout, &input, base + 4));
    var changed_files = actual;
    changed_files.first_touches.sha256[0] ^= 1;
    // Selection cannot depend on eventual source-file hashes. Final Plan must.
    var same_selection = try Selection.derive(a, try Selection.Authority.fromSources(changed_files), &input, &addresses, .{});
    defer same_selection.deinit();
    try std.testing.expectEqualDeep(selection.digest, same_selection.digest);
    var changed_plan = try Plan.derive(a, changed_files, &input, &addresses, .{});
    defer changed_plan.deinit();
    try std.testing.expect(!std.meta.eql(final.digest, changed_plan.digest));
    var inspected = try Proposal.inspect(a, &selection, pins(&selection), &input, try sourcePin(), &events(), .{});
    defer inspected.deinit(a);
    const proposal = inspectedProposal(try sourcePin(), &selection, inspected);
    var bound = try proposal.bindPlan(a, proposal.expected, pins(&selection), &input, actual, try actual.digest());
    defer bound.deinit();
    try std.testing.expectEqualDeep(final.digest, bound.plan.digest);
    try std.testing.expectEqualDeep(Proposal.Census{ .all_rw = 3, .mutable = 1, .readonly = 2 }, bound.expected.census);
}
test "block-v5 readonly proposal rejects stale source layout bytes subset caps roots and census" {
    const a = std.testing.allocator;
    const actual = try sources();
    var selection = try Selection.derive(a, try Selection.Authority.fromSources(actual), &input, &addresses, .{});
    defer selection.deinit();
    var inspected = try Proposal.inspect(a, &selection, pins(&selection), &input, try sourcePin(), &events(), .{});
    defer inspected.deinit(a);
    const proposal = inspectedProposal(try sourcePin(), &selection, inspected);
    var changed = actual;
    changed.initial_rw_root[0] ^= 1;
    try std.testing.expectError(error.StaleReadonlyInputSourceAuthority, proposal.bindPlan(a, proposal.expected, pins(&selection), &input, changed, try changed.digest()));
    changed = actual;
    changed.layout.input_end += 4;
    try std.testing.expectError(error.StaleReadonlyInputSourceAuthority, proposal.bindPlan(a, proposal.expected, pins(&selection), &input, changed, try changed.digest()));
    changed = actual;
    changed.first_touches.sha256[0] ^= 1;
    try std.testing.expectError(error.StaleReadonlyInputActualSourcePlan, proposal.bindPlan(a, proposal.expected, pins(&selection), &input, changed, try actual.digest()));
    var bytes = input;
    bytes[0] ^= 1;
    try std.testing.expectError(error.UntrustedReadonlyInputBytes, Selection.admit(a, pins(&selection), &bytes));
    var wrong_pins = pins(&selection);
    wrong_pins.addresses = &.{base};
    try std.testing.expectError(error.UntrustedReadonlyInputSelection, Selection.admit(a, wrong_pins, &input));
    wrong_pins = pins(&selection);
    wrong_pins.limits.max_words += 1;
    try std.testing.expectError(error.UntrustedReadonlyInputSelection, Selection.admit(a, wrong_pins, &input));
    const prior = selection.intervals[0].value;
    selection.intervals[0].value = 8;
    try std.testing.expectError(error.StaleReadonlyInputSelection, selection.require(pins(&selection), &input));
    selection.intervals[0].value = prior;
    var expected = proposal.expected;
    expected.census.readonly -= 1;
    expected.census.mutable += 1;
    try std.testing.expectError(error.StaleReadonlyInputPhysicalProposal, proposal.require(expected));
    expected = proposal.expected;
    expected.source.roots[0][0] ^= 1;
    try std.testing.expectError(error.StaleReadonlyInputPhysicalProposal, proposal.require(expected));
    expected = proposal.expected;
    expected.counter_digest[0] ^= 1;
    try std.testing.expectError(error.StaleReadonlyInputPhysicalProposal, proposal.require(expected));
    expected = proposal.expected;
    expected.event_digest[0] ^= 1;
    try std.testing.expectError(error.StaleReadonlyInputPhysicalProposal, proposal.require(expected));
    expected = proposal.expected;
    expected.source.roster_digest[0] ^= 1;
    try std.testing.expectError(error.StaleReadonlyInputPhysicalProposal, proposal.require(expected));
    const complete_events = events();
    try std.testing.expectError(error.StaleReadonlyInputCensus, Proposal.inspect(a, &selection, pins(&selection), &input, try sourcePin(), complete_events[0..2], .{}));
    var invalid_events = events();
    invalid_events[0].clock += 3;
    try std.testing.expectError(error.InvalidReadonlyInputSourceClock, Proposal.inspect(a, &selection, pins(&selection), &input, try sourcePin(), &invalid_events, .{}));
    invalid_events = events();
    invalid_events[0].after += 1;
    try std.testing.expectError(error.InvalidReadonlyInputClassification, Proposal.inspect(a, &selection, pins(&selection), &input, try sourcePin(), &invalid_events, .{}));
}
test "block-v5 readonly proposal real borrowed prefix and classifier commitments replay without STARK" {
    const a = std.testing.allocator;
    const Scheme = engine.pcs.CommitmentSchemeProver(Cpu, core.proof_suites.Blake3.Hasher, core.proof_suites.Blake3.MerkleChannel);
    var source = try sourcePin();
    var prefix = try Scheme.init(a, source.config);
    defer prefix.deinit(a);
    // Real bounded commitments only. No native/caller AIR authority claimed.
    const values = [_]M{ M.one(), M.one(), M.one(), M.zero(), M.zero(), M.zero(), M.zero(), M.zero() };
    const columns = [_]engine.pcs.ColumnEvaluation{.{ .values = &values, .log_size = 3 }};
    var channel = core.proof_suites.Blake3.Channel{};
    for (0..3) |_| try prefix.commitBorrowedStreaming(a, &columns, 1, &channel);
    var original = try prefix.roots(a);
    defer original.deinit(a);
    source.roots = original.items[0..2].*;
    source.access_root = original.items[2];
    const actual = try sources();
    var selection = try Selection.derive(a, try Selection.Authority.fromSources(actual), &input, &addresses, .{});
    defer selection.deinit();
    const Api = Proposal.ForBackend(Cpu);
    const proposal = try Api.collect(a, &selection, pins(&selection), &input, .{ .pcs = &prefix, .source = source }, &events(), .{});
    try proposal.require(proposal.expected);
    var bound = try proposal.bindPlan(a, proposal.expected, pins(&selection), &input, actual, try actual.digest());
    defer bound.deinit();
    const pin = Classification.Pin{ .plan_digest = bound.plan.digest, .source_identity = Sources.sha256("late actual post-seal source identity"), .events = source.all_rw_events, .row_log = source.row_log, .roots = proposal.expected.classifier_roots.?, .config = source.config };
    var trace = try Classification.Trace.init(a, bound.plan, &events(), pin);
    defer trace.deinit(a);
    var final_first = try Classification.ForBackend(Cpu).commit(a, &trace, pin);
    defer final_first.deinit(a);
    try std.testing.expectEqualDeep(proposal.expected.classifier_roots.?, final_first.roots);
    var after = try prefix.roots(a);
    defer after.deinit(a);
    try std.testing.expectEqual(original.items.len, after.items.len);
    for (original.items, after.items) |before, current| try std.testing.expectEqualDeep(before, current);
    // Same actual root ownership with a distinct independent caller role.
    var caller = source;
    caller.kind = .caller;
    const caller_proposal = try Api.collect(a, &selection, pins(&selection), &input, .{ .pcs = &prefix, .source = caller }, &events(), .{});
    try std.testing.expect(!std.meta.eql(proposal.expected.event_digest, caller_proposal.expected.event_digest));
    try std.testing.expectEqualDeep(proposal.expected.census, caller_proposal.expected.census);
    source.roots[0][0] ^= 1;
    try std.testing.expectError(error.StaleReadonlyInputPhysicalProposal, Api.collect(a, &selection, pins(&selection), &input, .{ .pcs = &prefix, .source = source }, &events(), .{}));
}
test "block-v5 readonly proposal empty subset zero source and all readonly preserve typed census" {
    const a = std.testing.allocator;
    const actual = try sources();
    var mutable = try Selection.derive(a, try Selection.Authority.fromSources(actual), &input, &.{}, .{});
    defer mutable.deinit();
    var all_mutable = try Proposal.inspect(a, &mutable, pins(&mutable), &input, try sourcePin(), &events(), .{});
    defer all_mutable.deinit(a);
    try std.testing.expectEqualDeep(Proposal.Census{ .all_rw = 3, .mutable = 3, .readonly = 0 }, all_mutable.census);
    var readonly = try Selection.derive(a, try Selection.Authority.fromSources(actual), &input, &.{ base, base + 4, base + 8 }, .{});
    defer readonly.deinit();
    var reads = events();
    reads[1].after = reads[1].before;
    var all_readonly = try Proposal.inspect(a, &readonly, pins(&readonly), &input, try sourcePin(), &reads, .{});
    defer all_readonly.deinit(a);
    try std.testing.expectEqualDeep(Proposal.Census{ .all_rw = 3, .mutable = 0, .readonly = 3 }, all_readonly.census);
    var absent = try sourcePin();
    absent.all_rw_events = 0;
    absent.row_log = 0;
    var no_rw = try Proposal.inspect(a, &readonly, pins(&readonly), &input, absent, &.{}, .{});
    defer no_rw.deinit(a);
    try std.testing.expect(no_rw.trace == null);
    const proposal = inspectedProposal(absent, &readonly, no_rw);
    try proposal.require(proposal.expected);
    try std.testing.expect(proposal.expected.classifier_roots == null);
    var bound = try proposal.bindPlan(a, proposal.expected, pins(&readonly), &input, actual, try actual.digest());
    defer bound.deinit();
    // Absence is physical only; no zero verified receipt is constructed.
    try std.testing.expectEqualDeep(Proposal.Census{ .all_rw = 0, .mutable = 0, .readonly = 0 }, bound.expected.census);
    absent.row_log = 3;
    try std.testing.expectError(error.InvalidReadonlyInputAbsentGeometry, absent.validate(.{}));
}
fn allocationLifecycle(a: std.mem.Allocator) !void {
    const actual = try sources();
    var selection = try Selection.derive(a, try Selection.Authority.fromSources(actual), &input, &addresses, .{});
    defer selection.deinit();
    var inspected = try Proposal.inspect(a, &selection, pins(&selection), &input, try sourcePin(), &events(), .{});
    defer inspected.deinit(a);
    const proposal = inspectedProposal(try sourcePin(), &selection, inspected);
    var bound = try proposal.bindPlan(a, proposal.expected, pins(&selection), &input, actual, try actual.digest());
    defer bound.deinit();
}
test "block-v5 readonly proposal selection trace actual source binding allocation failures clean" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationLifecycle, .{});
}
test "block-v5 readonly proposal actual collection binding and post seal bodies compile only" {
    inline for (.{ &Proposal.ForBackend(Cpu).collect, &Proposal.Proposal.bindPlan, &Proposal.Bound.pinAfterSeal, &Selection.admit }) |function| std.mem.doNotOptimizeAway(function);
}
