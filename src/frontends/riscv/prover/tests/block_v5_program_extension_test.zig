//! Caller quotient qualification only; fresh precompile arithmetic admission
//! remains a separate required authority before a production closure.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const source = @import("../block_v5_program_extension_source_v1.zig");
const request = @import("../block_v5_program_extension_proof_v1.zig");
const table = @import("../block_v5_program_table_proof_v1.zig");
const seal_mod = @import("../block_v5_source_seal_v1.zig");
const tree = @import("../../air/memory_commitment/blake3_state_tree.zig");
const sha = @import("../../air/guest_precompile/sha256_memory_caller.zig");
const keccak = @import("../../air/guest_precompile/keccakf_caller.zig");
const signer = @import("../../air/guest_precompile/secp256k1_recovery_caller.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;

test "block-v5 extension caller program quotient freshly closes three fetched tuples" {
    const a = std.testing.allocator;
    const kinds = [_]source.Kind{ .sha, .keccak, .signer };
    const widths = [_]usize{ sha.PHYSICAL_MAIN_COLUMN_COUNT, keccak.Layout.main_columns, signer.Layout.main_columns };
    var main: std.ArrayList(Column) = .empty;
    defer {
        for (main.items) |column| a.free(column.values);
        main.deinit(a);
    }
    var selector = [_]M{M.zero()} ** 128;
    selector[0] = M.one();
    const fixed = [_]Column{.{ .log_size = 7, .values = &selector }};
    var slots: [3]request.Slot = undefined;
    var leaves: [12]tree.Leaf = undefined;
    for (kinds, widths, &slots, 0..) |kind, width, *slot, index| {
        const offset = main.items.len;
        try main.ensureUnusedCapacity(a, width);
        for (0..width) |_| {
            const values = try a.alloc(M, 128);
            @memset(values, M.zero());
            main.appendAssumeCapacity(.{ .log_size = 7, .values = values });
        }
        const pc: u32 = 0x1000 + @as(u32, @intCast(index * 4));
        switch (kind) {
            .sha => {
                @constCast(main.items[offset + sha.Layout.pc].values)[0] = M.fromCanonical(pc);
                @constCast(main.items[offset + sha.Layout.registers].values)[0] = M.fromCanonical(5);
                @constCast(main.items[offset + sha.Layout.registers + 1].values)[0] = M.fromCanonical(6);
            },
            .keccak => {
                @constCast(main.items[offset + keccak.Layout.enabler].values)[0] = M.one();
                @constCast(main.items[offset + keccak.Layout.pc].values)[0] = M.fromCanonical(pc);
                @constCast(main.items[offset + keccak.Layout.pointer_register].values)[0] = M.fromCanonical(5);
            },
            .signer => {
                @constCast(main.items[offset + signer.Layout.is_active].values)[0] = M.one();
                @constCast(main.items[offset + signer.Layout.pc].values)[0] = M.fromCanonical(pc);
                @constCast(main.items[offset + signer.Layout.pointer_register].values)[0] = M.fromCanonical(5);
            },
        }
        slot.* = .{ .kind = kind, .log_size = 7, .active_calls = 1, .fixed_selector_offset = if (kind == .sha) 0 else null, .main_offset = offset, .main_columns = width };
        const row = try a.alloc(Q, width);
        defer a.free(row);
        for (row, main.items[offset..][0..width]) |*value, column|
            value.* = Q.fromBase(column.values[0]);
        const tuple = try source.fromCommittedCaller(kind, if (kind == .sha) &.{Q.one()} else &.{}, row);
        for (leaves[4 * index ..][0..4], tuple.tuple[1..], 0..) |*leaf, value, limb|
            leaf.* = .{ .index = pc + @as(u32, @intCast(limb)), .value = try base(value) };
    }
    const root = try tree.TreeHasher.init(.program).root(&leaves);
    const plan = @import("../block_v5_program_table_v1.zig").Plan{
        .program_root = root,
        .leaves = &leaves,
        .multiplicities = &.{ 1, 1, 1 },
        .expected_fetches = 3,
        .log_size = 7,
    };
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const RequestApi = request.ForBackend(Cpu);
    const TableApi = table.ForBackend(Cpu);
    const precompile_id: [32]u8 = @splat(41);
    const execution_id: [32]u8 = @splat(42);
    var first = try RequestApi.commitFirstRound(a, &fixed, main.items, &slots, precompile_id, execution_id, 0, config);
    defer first.deinit(a);
    var table_first = try TableApi.commitFirstRound(a, plan, config);
    defer table_first.deinit(a);
    var counts: [seal_mod.family_count]u32 = @splat(0);
    inline for ([_]seal_mod.Family{ .program, .execution, .execution_sidecar, .program_request, .memory, .precompile, .program_extension_request }) |family|
        counts[@intFromEnum(family) - 1] = 1;
    const pins = seal_mod.Pins{ .job_id = @splat(11), .source_image_digest = @splat(12), .native_template_id = @splat(13), .program_root = root.bytes, .program_plan_digest = try plan.digest(), .memory_plan_digest = @splat(14), .initial_source_plan_digest = @splat(15), .config = config, .counts = counts };
    const roster = [_]seal_mod.Entry{
        .{ .family = .program, .index = 0, .instance_id = try table.instanceId(plan), .roots = table_first.roots },
        .{ .family = .execution, .index = 0, .instance_id = execution_id, .roots = .{ @splat(1), @splat(2) } },
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(3), .roots = .{ @splat(4), @splat(5) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(6), .roots = .{ @splat(1), @splat(2) } },
        .{ .family = .memory, .index = 0, .instance_id = @splat(7), .roots = .{ @splat(8), @splat(9) } },
        .{ .family = .precompile, .index = 0, .instance_id = precompile_id, .roots = first.roots },
        .{ .family = .program_extension_request, .index = 0, .instance_id = request.instanceId(precompile_id, execution_id, 0, &slots), .roots = first.roots },
    };
    const sealed = try seal_mod.seal(pins, &roster);
    const seal = sealed.programSeal();
    const proved = try RequestApi.prove(a, &first, &fixed, main.items, &slots, seal, precompile_id, execution_id, 0, first.roots);
    const table_proved = try TableApi.prove(a, &table_first, plan, seal);
    var wrong_count = try clone(a, proved);
    wrong_count.claims[0].fetch_count += 1;
    try std.testing.expectError(error.InvalidProgramRequestCensus, RequestApi.verifyOwned(a, wrong_count, seal, 0, precompile_id, execution_id, &slots, first.fixed_logs, first.main_logs, first.roots, first.roots, config));
    if (RequestApi.verifyOwned(a, try clone(a, proved), seal, 0, precompile_id, @splat(43), &slots, first.fixed_logs, first.main_logs, first.roots, first.roots, config)) |_| {
        return error.AcceptedSwappedV5ExecutionInstance;
    } else |_| {}
    const receipt = try RequestApi.verifyOwned(a, proved, seal, 0, precompile_id, execution_id, &slots, first.fixed_logs, first.main_logs, first.roots, first.roots, config);
    const table_receipt = try TableApi.verifyOwned(a, table_proved, plan, seal, root, table_first.roots, config);
    try std.testing.expectEqual(@as(u64, 3), receipt.fetch_count);
    try table.closed(table_receipt, &.{receipt.closureReceipt()}, seal);
    try std.testing.expect(!std.meta.eql(roster[6].instance_id, request.instanceId(precompile_id, @splat(43), 0, &slots)));
    var changed = roster;
    changed[6].roots[1][0] ^= 1;
    try std.testing.expectError(error.UntrustedBlockV5SourceSeal, sealed.require(pins, &changed));
}

fn base(value: Q) !u32 {
    const limbs = value.toM31Array();
    for (limbs[1..]) |limb| if (!limb.isZero()) return error.NonBaseProgramRequest;
    return limbs[0].toU32();
}

fn clone(a: std.mem.Allocator, proof: request.Proof) !request.Proof {
    const postcard = @import("interop_postcard");
    var writer = std.Io.Writer.Allocating.init(a);
    defer writer.deinit();
    try postcard.serializeProof(core.proof_suites.Blake3.Hasher, &writer.writer, proof.stark);
    var stream = std.io.fixedBufferStream(writer.written());
    var stark = try postcard.deserializeProof(core.proof_suites.Blake3.Hasher, a, stream.reader());
    errdefer stark.deinit(a);
    return .{ .stark = stark, .claims = try a.dupe(request.Claim, proof.claims) };
}
