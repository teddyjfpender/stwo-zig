const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const tree = @import("../../air/memory_commitment/blake3_state_tree.zig");
const opcode = @import("../../runner/trace.zig");
const source = @import("../block_v5_program_request_source_v1.zig");
const requests = @import("../block_v5_program_request_proof_v1.zig");
const table_source = @import("../block_v5_program_table_v1.zig");
const table_proof = @import("../block_v5_program_table_proof_v1.zig");
const block_seal = @import("../block_v5_source_seal_v1.zig");

test "block-v5 same-root opcode request proof freshly closes authenticated ROM table" {
    const a = std.testing.allocator;
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const RequestApi = requests.ForBackend(Cpu);
    const TableApi = table_proof.ForBackend(Cpu);
    const M = core.fields.m31.M31;
    const Q = core.fields.qm31.QM31;
    const family: opcode.OpcodeFamily = .base_alu_imm;
    var execution = opcode.Trace.init(a);
    defer execution.deinit();
    try execution.append(.{
        .clk = 1,
        .pc = 0x1000,
        .opcode = .ADDI,
        .rd = 1,
        .rs1 = 0,
        .rs2 = 0,
        .imm = 1,
        .rs1_val = 0,
        .rs2_val = 0,
        .rd_val = 1,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = 0x1004,
        .inst_word = 0x00100093,
    });
    var main_trace = try execution.columnsForFamily(a, family, 7);
    defer main_trace.deinit(a);
    const native_main = try a.alloc(engine.pcs.ColumnEvaluation, main_trace.n_columns);
    defer a.free(native_main);
    for (main_trace.columns[0..main_trace.n_columns], native_main) |values, *column|
        column.* = .{ .log_size = 7, .values = values };
    const fixed_values = [_]M{M.zero()} ** 128;
    const native_fixed = [_]engine.pcs.ColumnEvaluation{.{ .log_size = 7, .values = &fixed_values }};
    var row: [opcode.MAX_FAMILY_COLUMNS]Q = undefined;
    for (row[0..main_trace.n_columns], native_main) |*value, column| value.* = Q.fromBase(column.values[0]);
    const fetch = try source.fromCommittedOpcodeMain(Q, family, row[0..main_trace.n_columns]);
    var leaves: [4]tree.Leaf = undefined;
    const address = try base(fetch.tuple[0]);
    for (&leaves, fetch.tuple[1..5], 0..) |*leaf, value, i| leaf.* = .{ .index = address + @as(u32, @intCast(i)), .value = try base(value) };
    const program_root = try tree.TreeHasher.init(.program).root(&leaves);
    const counts = [_]u64{1};
    const plan = table_source.Plan{ .program_root = program_root, .leaves = &leaves, .multiplicities = &counts, .expected_fetches = 1, .log_size = 7 };
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var table_first = try TableApi.commitFirstRound(a, plan, config);
    defer table_first.deinit(a);
    const slot = requests.Slot{ .family = family, .log_size = 7, .n_rows = 1, .main_offset = 0 };
    const slots = [_]requests.Slot{slot};
    const key_id: [32]u8 = @splat(17);
    var request_first = try RequestApi.commitFirstRound(a, &native_fixed, native_main, &slots, key_id, 0, config);
    defer request_first.deinit(a);
    var family_counts: [block_seal.family_count]u32 = @splat(0);
    inline for ([_]block_seal.Family{ .program, .execution, .execution_sidecar, .program_request, .memory }) |kind|
        family_counts[@intFromEnum(kind) - 1] = 1;
    const pins = block_seal.Pins{ .job_id = @splat(11), .source_image_digest = @splat(12), .native_template_id = @splat(13), .program_root = program_root.bytes, .program_plan_digest = try plan.digest(), .memory_plan_digest = @splat(14), .initial_source_plan_digest = @splat(15), .config = config, .counts = family_counts };
    const roster = [_]block_seal.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(21), .roots = table_first.roots },
        .{ .family = .execution, .index = 0, .instance_id = key_id, .roots = request_first.roots },
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(22), .roots = .{ @splat(31), @splat(32) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(23), .roots = request_first.roots },
        .{ .family = .memory, .index = 0, .instance_id = @splat(24), .roots = .{ @splat(33), @splat(34) } },
    };
    const sealed = try block_seal.seal(pins, &roster);
    try sealed.require(pins, &roster);
    var changed_roster = roster;
    changed_roster[3].roots[1][0] ^= 1;
    try std.testing.expectError(error.UntrustedBlockV5SourceSeal, sealed.require(pins, &changed_roster));
    const seal = sealed.programSeal();
    try seal.validate(plan, table_first.roots);
    const table_proved = try TableApi.prove(a, &table_first, plan, seal);
    const request_proved = try RequestApi.prove(a, &request_first, native_main, &slots, seal, key_id, 0, request_first.roots);
    const table_receipt = try TableApi.verifyOwned(a, table_proved, plan, seal, program_root, table_first.roots, config);
    const request_receipt = try RequestApi.verifyOwned(a, request_proved, seal, 0, key_id, &slots, request_first.fixed_logs, request_first.main_logs, request_first.roots, request_first.roots, config);
    try std.testing.expectEqual(@as(u64, 1), request_receipt.fetch_count);
    try table_proof.closed(table_receipt, &.{request_receipt.closureReceipt()}, seal);
}

fn base(value: core.fields.qm31.QM31) !u32 {
    const limbs = value.toM31Array();
    for (limbs[1..]) |limb| if (!limb.isZero()) return error.NonBaseProgramRequest;
    return limbs[0].toU32();
}
