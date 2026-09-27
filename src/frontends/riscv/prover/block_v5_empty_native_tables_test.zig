//! Pure branch/identity guards. These synthetic receipts are not native proof
//! qualification; the production hook receives only the fresh native verifier.
const std = @import("std");
const core = @import("stwo_core");
const Empty = @import("block_v5_empty_native_tables_v1.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Public = @import("block_v5_native_public_admission_v1.zig");
const Template = @import("block_v5_native_template_protocol_v3.zig");
const Catalog = @import("block_v5_native_template_catalog_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Native = @import("block_v5_native_execution_proof_v3.zig");
const Q = core.fields.qm31.QM31;

test "block-v5 empty native table branch retains PC compensation and rejects clock geometry" {
    const a = std.testing.allocator;
    var shape: Shape = undefined;
    shape.initializeDescriptorStorage();
    shape.n_components = 0;
    shape.n_infra = 0;
    shape.initial_pc = 0x1000;
    shape.final_pc = 0x100c;
    shape.total_steps = 3;
    shape.public_data = .{
        .initial_pc = shape.initial_pc,
        .final_pc = shape.final_pc,
        .clock = shape.total_steps,
        .initial_regs = @splat(0),
        .final_regs = @splat(0),
        .reg_last_clock = @splat(0),
        .program_root = .{ .bytes = @splat(3) },
        .initial_rw_root = null,
        .final_rw_root = null,
        .completion = @import("../air/public_data.zig").Completion.canonicalSelfLoop(shape.final_pc),
        .io_entries = .{ .input_start = 0x2000, .input_len = 0, .input_words = &.{}, .output_len = 0, .output_len_addr = 0x3004, .output_data_addr = 0x3008, .output_words = &.{} },
    };
    try Empty.validateShape(a, &shape, 3);
    try std.testing.expectError(error.InvalidV5EmptyProgramShape, Empty.validateShape(a, &shape, 0));
    try std.testing.expectError(error.InvalidV5EmptyProgramShape, Empty.validateShape(a, &shape, 2));
    var clock = shape;
    clock.n_infra = 1;
    clock.infra_descs[0] = .{ .kind = .clock_update, .log_size = 1, .n_rows = 1, .n_columns = 10 };
    try clock.validateBlake3ExecutionWithExternal(3);
    try std.testing.expectError(error.NonemptyV5NativeLookupGeometry, Empty.validateShape(a, &clock, 3));
    const slots = try @import("block_v5_native_lookup_request_source_v1.zig").slotsFromShape(a, &clock, 3);
    defer a.free(slots);
    try std.testing.expectEqual(@as(usize, 3), slots.len);
    const demand = try @import("block_v5_native_lookup_plan_v1.zig").nativeDemand(&clock, 3);
    try std.testing.expectEqual(@as(u64, 1), demand[1]);
    try std.testing.expectEqual(@as(u64, 1), demand[4]);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const admission = try Public.Admission.init(.{ .job_id = @splat(1), .source_image_digest = @splat(2), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .rw_endpoint_plan_digest = @splat(7), .execution_index = 0, .first_cycle = 1, .last_cycle = 3 }, &shape.public_data);
    const template = try Template.Template.fromShape(&shape, config, .rv32im_zkvm_ethereum_sha_v1, 3, @splat(8));
    const template_id = try template.identity();
    const records = [_]Catalog.Record{.{ .index = 0, .template_id = template_id, .geometry_digest = template.geometry_digest, .fixed_root = template.fixed_root }};
    const catalog = Catalog.Admission{ .records = &records };
    const roots: Seal.Roots = .{ template.fixed_root, @splat(9) };
    const instance = try Template.instanceId(template_id, &shape, admission, roots, 0);
    var counts: [Seal.family_count]u32 = @splat(0);
    inline for ([_]Seal.Family{ .program, .execution, .execution_sidecar, .program_request, .memory }) |kind| counts[@intFromEnum(kind) - 1] = 1;
    const pins = Seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_catalog_digest = try catalog.digest(), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .rw_endpoint_plan_digest = @splat(7), .config = config, .counts = counts };
    const entries = [_]Seal.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
        .{ .family = .execution, .index = 0, .instance_id = instance, .roots = roots },
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(13), .roots = .{ @splat(14), @splat(15) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(16), .roots = roots },
        .{ .family = .memory, .index = 0, .instance_id = @splat(17), .roots = .{ @splat(18), @splat(19) } },
    };
    const sealed = try Seal.seal(pins, &entries);
    var channel = sealed.sharedChannel();
    const universal = try @import("../recursion/air/universal_challenges.zig").UniversalRelations.draw(a, &channel);
    const relations = try @import("../recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(&universal);
    const expected_pc = try @import("../air/public_logup_arithmetic.zig").registersStateSumFor(Q, &shape.public_data, &relations.native);
    var fresh = Native.OpenReceipt{ .template_id = template_id, .instance_id = instance, .first_roots = roots, .sealed_digest = sealed.digest, .open_sum = expected_pc };
    const independent = Empty.Pins{ .shape = &shape, .admission = admission, .template = template, .template_id = template_id, .catalog = catalog };
    const partition = try Empty.fromFresh(a, independent, &fresh, 0, sealed, pins, &entries);
    try std.testing.expectEqualDeep(expected_pc, partition.public_state_sum);
    try std.testing.expect(!partition.public_state_sum.isZero());
    for (partition.claims) |sum| try std.testing.expect(sum.isZero());
    try std.testing.expect(partition.auxiliary_clock_memory_sum.isZero());
    fresh.open_sum = expected_pc.add(Q.one());
    try std.testing.expectError(error.UntrustedV5EmptyNativeOpenClaim, Empty.fromFresh(a, independent, &fresh, 0, sealed, pins, &entries));
    fresh.open_sum = expected_pc;
    fresh.first_roots[1][0] ^= 1;
    try std.testing.expectError(error.UntrustedV5EmptyNativeTables, Empty.fromFresh(a, independent, &fresh, 0, sealed, pins, &entries));
}
