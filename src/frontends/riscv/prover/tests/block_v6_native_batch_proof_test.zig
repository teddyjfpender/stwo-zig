//! Real adjacent native proofs -> one recursive proof, without leaf wrappers.
//! The global provider roster is intentionally open in this focused fixture.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const preparation = @import("../../recursion/block_v6_native_batch_prepare_v1.zig");
const bus = @import("../../recursion/block_v6_native_batch_public_v1.zig");
const protocol = @import("../../recursion/block_v6_native_batch_protocol_v1.zig");
const parent = @import("../../recursion/blake3_execution_parent_proof.zig");
const fixture = @import("block_v5_lightweight_native_proof_test.zig");

test "block-v6 direct native batch q8 has no individual recursive wrappers" {
    try run(.diagnostic_q8_pow0, true);
}
test "block-v6 direct native batch canonical q70 pow26" {
    try run(.csp_q70_pow26, true);
}
test "block-v6 canonical wrapper comparison baseline" {
    try run(.csp_q70_pow26, false);
}

fn run(comptime selected: parent.protocol.Profile, comptime direct: bool) !void {
    const engine = @import("stwo_prover_engine");
    const workers = if (std.posix.getenv("STWO_NATIVE_BATCH_WORKERS")) |raw| try std.fmt.parseInt(usize, raw, 10) else 0;
    var pool: engine.work_pool.WorkPool = undefined;
    if (workers != 0) try pool.initInPlaceWithOptions(.{ .worker_count = workers, .backing_allocator = std.testing.allocator });
    defer if (workers != 0) pool.deinit();
    var binding: ?engine.work_pool.ScopedPoolBinding = if (workers != 0) try .init(&pool) else null;
    defer if (binding) |*owned| owned.deinit();
    std.debug.print("BLOCK_V6_BENCH_ENV workers={d} direct={any} profile={s}\n", .{ workers, direct, @tagName(selected) });
    try fixture.qualifyWithProfile(true, false, selected, direct);
}

pub fn qualify(a: std.mem.Allocator, admissions: []const *const preparation.NativeAdmission, captures: []const *const preparation.Capture, selected: parent.protocol.Profile, native_ns: u64) !void {
    var timer = try std.time.Timer.start();
    var prepared = try preparation.prepare(a, admissions, captures, 2);
    defer prepared.deinit();
    const prepare_ns = timer.lap();
    const geometry = try parent.ForBackend(Cpu).deriveKeyWithProfile(a, &prepared.recursive, selected);
    const key = try protocol.Key.fromGeometry(geometry, prepared.wires, admissions.len);
    const expected = try key.identity();
    const authority = try protocol.Admission.init(key, expected, prepared.wires, prepared.values());
    const Plan = @import("../../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Cpu, protocol);
    const plan = try Plan.init(a, &prepared.recursive.rows, authority);
    defer plan.deinit();
    const setup_ns = timer.lap();
    var proof = try plan.prove(a, &prepared.recursive.rows);
    defer proof.deinit();
    const prove_ns = timer.lap();
    const bytes = try parent.codec.encode(a, &proof, &authority);
    defer a.free(bytes);
    // Derive independent public values again from the original policies and
    // native exported receipts. No output descriptor from preparation is used.
    const children = try a.alloc(bus.Child, admissions.len);
    defer a.free(children);
    for (admissions, captures, children) |admitted, capture, *child| child.* = try preparation.publicChild(a, admitted, capture.receipt);
    const fresh_authority = try protocol.Admission.init(key, expected, prepared.wires, .{ .children = children });
    var decoded = try parent.codec.decode(a, bytes, &fresh_authority);
    var fresh = try parent.verify(&decoded, &fresh_authority);
    defer fresh.deinit();
    try fresh.validate(&fresh_authority, expected);
    const span = try fresh_authority.values.outputSpan();
    try std.testing.expectEqual(@as(u32, @intCast(admissions.len)), span.segment_count);
    const verify_ns = timer.lap();

    const original = children[1];
    children[1].native.open_sum = original.native.open_sum.add(core.fields.qm31.QM31.one());
    try std.testing.expectError(error.InvalidNativeBatchPublicClosure, fresh.validate(&fresh_authority, expected));
    children[1] = original;
    children[1].span.initial_pc ^= 4;
    try std.testing.expectError(error.DiscontinuousV5PcClockSpan, fresh_authority.validate());
    children[1] = children[0];
    try std.testing.expectError(error.DiscontinuousV5PcClockSpan, fresh_authority.validate());
    children[1] = original;
    // Bypass host adjacency preflight and exercise the emitted arithmetic graph.
    var edge_wires: std.ArrayList(bus.Wire) = .empty;
    defer edge_wires.deinit(a);
    inline for (.{ "initial_pc", "first_cycle", "first_index" }) |field| {
        if (comptime std.mem.eql(u8, field, "initial_pc")) {
            @field(children[1].span, field) += 1;
        } else {
            // Keep each span individually valid, but break the join edge.
            @field(children[1].span, field) -= 1;
        }
        try std.testing.expectError(error.UnsatisfiedCircuit, @import("../../recursion/air/block_v6_native_batch_edges_v1.zig").append(&prepared.recursive.rows, children, 1_500_000_000, &edge_wires));
        children[1] = original;
    }
    var wrong = fresh_authority;
    wrong.values.children = children[0..1];
    try std.testing.expectError(error.InvalidNativeBatchAdmission, wrong.validate());
    wrong = fresh_authority;
    wrong.expected_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedNativeBatchKey, wrong.validate());
    try std.testing.expectError(error.InvalidNativeBatchCount, (bus.Values{ .children = &.{} }).validate());
    // Changed native proof claims cannot enter the batch under an old capture.
    var changed_capture = captures[0].*;
    changed_capture.receipt.open_sum = changed_capture.receipt.open_sum.add(core.fields.qm31.QM31.one());
    if (preparation.prepare(a, admissions, &.{ &changed_capture, captures[1] }, 2)) |unexpected| {
        var owned = unexpected;
        owned.deinit();
        return error.AcceptedChangedNativeCapture;
    } else |_| {}
    const costs = work(&prepared.recursive.rows);
    std.debug.print("BLOCK_V6_DIRECT_NATIVE verified=true profile={s} children=2 native_ns={d} prepare_ns={d} setup_ns={d} prove_ns={d} encode_verify_ns={d} recursive_ns={d} g_rows={d} air_cells={d} proof_bytes={d} globals_open=true\n", .{
        @tagName(selected),                           native_ns,    prepare_ns,  setup_ns,  prove_ns, verify_ns,
        prepare_ns + setup_ns + prove_ns + verify_ns, costs.g_rows, costs.cells, bytes.len,
    });
}

pub const Work = struct { cells: usize = 0, g_rows: usize = 0 };
/// Committed AIR area only: excludes shared lookup tables, PCS expansion and
/// quotient scratch. Both sides of the comparison use this exact counter.
pub fn work(rows: *const @import("../../recursion/air/blake3_parent_row_storage.zig").Prepared) Work {
    var result: Work = .{};
    const Storage = @import("../../recursion/air/blake3_parent_row_storage.zig");
    inline for (Storage.Airs, 0..) |Air, i| {
        const count = rows.fixed[i].len;
        const log = if (count <= 1) 1 else std.math.log2_int_ceil(usize, count);
        result.cells += (@as(usize, 1) << @intCast(log)) * (Air.PREPROCESSED_COLUMN_COUNT + Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.INTERACTION_COLUMN_COUNT);
        if (Air == @import("../../recursion/air/blake3_g_call.zig")) result.g_rows += count;
    }
    return result;
}
