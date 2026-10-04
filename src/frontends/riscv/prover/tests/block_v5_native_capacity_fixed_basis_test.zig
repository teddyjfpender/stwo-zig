//! Nonproving basis admission/body fixtures. Tests named "capacity fixed lease"
//! additionally commit two tiny CPU trees (maximum trace log 3); they do not
//! execute a guest, generate interactions, prove, fold FRI or use a device.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Basis = @import("../block_v5_native_capacity_fixed_basis_v1.zig");
const Protocol = @import("../block_v5_native_capacity_protocol_v1.zig");
const Activity = @import("../block_v5_native_capacity_activity_v1.zig");
const Capacity = @import("../block_v5_native_capacity_proof_v1.zig");
const Statement = @import("../../air/statement.zig");
const Public = @import("../block_v5_native_public_admission_v1.zig");
const Profile = @import("../../isa/execution_profile.zig").ExecutionProfile;
const suite = core.proof_suites.Blake3;
const config = @import("../../recursion/blake3_execution_parent_protocol.zig").PCS_CONFIG;
const selected = Profile.rv32im_zkvm_v1;
const Owner = Basis.ForBackend(Cpu).Owner;
const Scheme = engine.pcs.CommitmentSchemeProver(Cpu, suite.Hasher, suite.MerkleChannel);
// Hard tiny fixture caps, independent of larger production defaults.
const limits = Basis.Limits{ .max_columns = 2, .max_log = 3, .max_retained_bytes = 128 << 10 };

fn shape(rows: u32) Statement.Blake3ExecutionStatement {
    var result = std.mem.zeroes(Statement.Blake3ExecutionStatement);
    result.initializeDescriptorStorage();
    result.n_components = 1;
    result.component_descs[0] = .{ .family = .base_alu_imm, .log_size = @max(1, std.math.log2_int_ceil(u32, rows)), .n_rows = rows, .n_columns = @intCast(@import("../../runner/trace.zig").nColumnsForFamily(.base_alu_imm)) };
    result.total_steps = rows;
    result.public_data = .{ .initial_pc = 0, .final_pc = 0, .clock = rows, .initial_regs = @splat(0), .final_regs = @splat(0), .reg_last_clock = @splat(0), .program_root = .{ .bytes = @splat(3) }, .initial_rw_root = null, .final_rw_root = null, .completion = @import("../../air/public_data.zig").Completion.canonicalSelfLoop(0), .io_entries = .{ .input_start = 0x2000, .input_len = 0, .input_words = &.{}, .output_len = 0, .output_len_addr = 0x3004, .output_data_addr = 0x3008, .output_words = &.{} } };
    return result;
}
fn firstChannel(index: u32) suite.Channel {
    var channel = suite.Channel{};
    channel.mixU32s(&.{ Protocol.TAG, Protocol.VERSION, 0, index });
    return channel;
}

test "capacity fixed admission exact retained bound rejects columns logs bytes and invalid config" {
    const expected: usize = (64 << 10) + 2 * (16 + 8) * @sizeOf(core.fields.m31.M31) + 2 * 16 * @sizeOf(Protocol.Digest) + 2 * 16 * @sizeOf(core.fields.m31.M31);
    try std.testing.expectEqual(expected, try limits.requiredBytes(&.{ 3, 3 }, config));
    try std.testing.expectError(error.NativeCapacityFixedBasisResourceLimit, (Basis.Limits{ .max_retained_bytes = expected - 1 }).requiredBytes(&.{ 3, 3 }, config));
    try std.testing.expectError(error.NativeCapacityFixedBasisResourceLimit, limits.requiredBytes(&.{ 3, 3, 3 }, config));
    try std.testing.expectError(error.NativeCapacityFixedBasisResourceLimit, limits.requiredBytes(&.{4}, config));
    try std.testing.expectError(error.NativeCapacityFixedBasisResourceLimit, limits.requiredBytes(&.{0}, config));
    try std.testing.expectError(error.NativeCapacityFixedBasisResourceLimit, limits.requiredBytes(&.{}, config));
    try std.testing.expectError(error.NativeCapacityFixedBasisResourceLimit, (Basis.Limits{ .max_log = 25 }).requiredBytes(&.{1}, config));
    var invalid = config;
    invalid.fri_config.n_queries = 0;
    try std.testing.expectError(error.InvalidExecutionConfig, limits.requiredBytes(&.{1}, invalid));
    // The retained cap is checked before fixed rows or PCS tree allocation,
    // after only bounded descriptor generation.
    const a = std.testing.allocator;
    var source = shape(5);
    const bound = try limits.requiredBytes(&.{ 3, 3 }, config);
    try std.testing.expectError(error.NativeCapacityFixedBasisResourceLimit, Owner.init(a, &source, 0, config, selected, .{ .max_retained_bytes = bound - 1 }));
}

test "capacity fixed lease cold warm transcripts and main roots agree with fresh fixed reconstruction" {
    const a = std.testing.allocator;
    var first = shape(5);
    var second = shape(7);
    var basis = try Owner.init(a, &first, 0, config, selected, limits);
    defer basis.deinit();
    const fixed_root = basis.template.fixed_root;
    var warm_main_roots: [2]Protocol.Digest = undefined;
    for ([_]*const Statement.Blake3ExecutionStatement{ &first, &second }, 0..) |source, ordinal| {
        var warm_channel = firstChannel(@intCast(ordinal));
        var cold_channel = firstChannel(@intCast(ordinal));
        var warm = try basis.lease(a, source, 0, config, selected, &warm_channel);
        defer warm.deinit(a);
        var cold = try Scheme.init(a, config);
        defer cold.deinit(a);
        cold.setCoefficientRetentionPolicy(.never);
        const fixed = try Protocol.fixedColumns(a, source, 0);
        defer Protocol.freeColumns(a, fixed);
        try cold.commitBorrowedStreaming(a, fixed, 8, &cold_channel);
        var cold_roots = try cold.roots(a);
        defer cold_roots.deinit(a);
        try std.testing.expectEqualDeep(fixed_root, cold_roots.items[0]);
        try std.testing.expectEqualDeep(cold_channel.digestBytes(), warm_channel.digestBytes());
        // Activity/count are genuine committed instance columns. This fixture
        // does not assert that these two columns constitute native execution.
        const plan = try Protocol.Plan.fromShape(source, 0);
        const main = try Activity.columns(a, &plan);
        defer Protocol.freeColumns(a, main);
        try cold.commitBorrowedStreaming(a, main, 8, &cold_channel);
        try warm.commitBorrowedStreaming(a, main, 8, &warm_channel);
        var cold_first = try cold.roots(a);
        defer cold_first.deinit(a);
        var warm_first = try warm.roots(a);
        defer warm_first.deinit(a);
        try std.testing.expectEqualSlices(Protocol.Digest, cold_first.items, warm_first.items);
        try std.testing.expectEqualDeep(cold_channel.digestBytes(), warm_channel.digestBytes());
        try std.testing.expect(warm.trees.items[0].columns.ptr == basis.scheme.trees.items[0].columns.ptr);
        try std.testing.expect(warm.trees.items[0].coefficients.?.ptr == basis.scheme.trees.items[0].coefficients.?.ptr);
        try std.testing.expect(cold.trees.items[0].columns.ptr != warm.trees.items[0].columns.ptr);
        warm_main_roots[ordinal] = warm_first.items[1];
        try basis.require(a, source, 0, config, selected);
    }
    try std.testing.expect(!std.meta.eql(warm_main_roots[0], warm_main_roots[1]));
}

test "capacity fixed lease rejects profile config roster root log and stale owner mismatches" {
    const a = std.testing.allocator;
    var source = shape(5);
    var same_bucket = shape(7);
    var basis = try Owner.init(a, &source, 0, config, selected, limits);
    defer basis.deinit();
    try basis.require(a, &same_bucket, 0, config, selected);
    var other_bucket = shape(9);
    try std.testing.expectError(error.UntrustedNativeCapacityTemplate, basis.require(a, &other_bucket, 0, config, selected));
    var other_roster = source;
    other_roster.component_descs[0].family = .base_alu_reg;
    other_roster.component_descs[0].n_columns = @intCast(@import("../../runner/trace.zig").nColumnsForFamily(.base_alu_reg));
    try std.testing.expectError(error.UntrustedNativeCapacityTemplate, basis.require(a, &other_roster, 0, config, selected));
    try std.testing.expectError(error.UntrustedNativeCapacityFixedBasis, basis.require(a, &source, 0, config, .rv32im_zkvm_ethereum_sha_v1));
    var changed_config = config;
    changed_config.pow_bits = 1;
    try std.testing.expectError(error.UntrustedNativeCapacityFixedBasis, basis.require(a, &source, 0, changed_config, selected));
    const id = basis.template_id;
    basis.template_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedNativeCapacityTemplate, basis.require(a, &source, 0, config, selected));
    const legacy = try @import("../block_v5_native_template_protocol_v3.zig").Template.fromShape(&source, config, selected, 0, basis.template.fixed_root);
    basis.template_id = try legacy.identity();
    try std.testing.expectError(error.UntrustedNativeCapacityTemplate, basis.require(a, &source, 0, config, selected));
    basis.template_id = id;
    const root = basis.template.fixed_root;
    basis.template.fixed_root[0] ^= 1;
    try std.testing.expectError(error.UntrustedNativeCapacityTemplate, basis.require(a, &source, 0, config, selected));
    basis.template.fixed_root = root;
    const log = basis.scheme.trees.items[0].columns[0].log_size;
    basis.scheme.trees.items[0].columns[0].log_size += 1;
    try std.testing.expectError(error.UntrustedNativeCapacityFixedBasis, basis.require(a, &source, 0, config, selected));
    basis.scheme.trees.items[0].columns[0].log_size = log;
    var channel = firstChannel(0);
    basis.deinit();
    try std.testing.expectError(error.InvalidNativeCapacityFixedBasisPhase, basis.lease(a, &source, 0, config, selected, &channel));
}

test "capacity fixed lease outlives cache owner with coefficient views and independent channels" {
    const a = std.testing.allocator;
    var source = shape(5);
    var basis = try Owner.init(a, &source, 0, config, selected, limits);
    defer basis.deinit();
    var one_channel = firstChannel(0);
    var two_channel = firstChannel(1);
    var one = try basis.lease(a, &source, 0, config, selected, &one_channel);
    defer one.deinit(a);
    var two = try basis.lease(a, &source, 0, config, selected, &two_channel);
    defer two.deinit(a);
    const fixed_root = basis.template.fixed_root;
    const first_coeff = two.trees.items[0].coefficients.?[0].coefficients()[0];
    try std.testing.expect(!std.meta.eql(one_channel.digestBytes(), two_channel.digestBytes()));
    one.trees.items[0].releaseCoefficients(a);
    try std.testing.expect(one.trees.items[0].coefficients == null);
    try basis.require(a, &source, 0, config, selected);
    try std.testing.expect(two.trees.items[0].coefficients != null);
    basis.deinit();
    try std.testing.expectEqualDeep(fixed_root, two.trees.items[0].root());
    try std.testing.expectEqualDeep(first_coeff, two.trees.items[0].coefficients.?[0].coefficients()[0]);
    // After the original cache scheme/twiddle provider is gone, each lease
    // independently commits fresh main state using its own twiddle provider.
    const plan = try Protocol.Plan.fromShape(&source, 0);
    const main = try Activity.columns(a, &plan);
    defer Protocol.freeColumns(a, main);
    try one.commitBorrowedStreaming(a, main, 8, &one_channel);
    try two.commitBorrowedStreaming(a, main, 8, &two_channel);
    var roots = try two.roots(a);
    defer roots.deinit(a);
    try std.testing.expectEqual(@as(usize, 2), roots.items.len);
    try std.testing.expectEqualDeep(fixed_root, roots.items[0]);
    var opening = try two.trees.items[0].decommit(a, &.{ 0, 2 });
    defer opening.deinit(a);
}

fn allocationOwnership(a: std.mem.Allocator) !void {
    var source = shape(3);
    var basis = try Owner.init(a, &source, 0, config, selected, limits);
    defer basis.deinit();
    var channel = firstChannel(0);
    var lease = try basis.lease(a, &source, 0, config, selected, &channel);
    defer lease.deinit(a);
    const plan = try Protocol.Plan.fromShape(&source, 0);
    const main = try Activity.columns(a, &plan);
    defer Protocol.freeColumns(a, main);
    basis.deinit();
    try lease.commitBorrowedStreaming(a, main, 8, &channel);
    var roots = try lease.roots(a);
    defer roots.deinit(a);
    try std.testing.expectEqual(@as(usize, 2), roots.items.len);
}
test "capacity fixed lease every allocation failure preserves cache and acquired tree ownership" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationOwnership, .{});
}

fn physicalBody(a: std.mem.Allocator, source: *@import("../blake3_execution_trace.zig").Owner, basis: *Owner) anyerror!Capacity.ForBackend(Cpu).PhysicalFirstRound {
    return Capacity.ForBackend(Cpu).commitPhysicalWithBasis(a, source, config, selected, 0, .{}, basis);
}
fn firstBody(a: std.mem.Allocator, source: *@import("../blake3_execution_trace.zig").Owner, pin: Public.Admission, basis: *Owner) anyerror!Capacity.ForBackend(Cpu).FirstRound {
    return Capacity.ForBackend(Cpu).commitFirstRoundWithBasis(a, source, pin, config, selected, 0, .{}, basis);
}
fn collectBody(a: std.mem.Allocator, source: *@import("../blake3_execution_trace.zig").Owner, basis: *Owner) anyerror!Capacity.Proposal {
    return Capacity.ForBackend(Cpu).collectWithBasis(a, source, config, selected, 0, .{}, basis);
}
test "capacity fixed admission cached and uncached real producer and independent receiver bodies compile only" {
    inline for (.{ &physicalBody, &firstBody, &collectBody }) |function| std.mem.doNotOptimizeAway(function);
    const Api = Capacity.ForBackend(Cpu);
    inline for (.{ &Api.commitPhysical, &Api.commitFirstRound, &Api.collect, &Api.prove, &Api.verifyOwned }) |function| std.mem.doNotOptimizeAway(function);
}
