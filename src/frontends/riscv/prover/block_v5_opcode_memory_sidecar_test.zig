const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const runner = @import("../runner/mod.zig");
const public = @import("blake3_segment_public.zig");
const custody = @import("blake3_commitment_witness.zig");
const plan_mod = @import("blake3_commitment_plan.zig");
const native_mod = @import("blake3_execution_trace.zig");
const native_proof = @import("block_v5_native_execution_proof_v1.zig");
const sidecar = @import("block_v5_opcode_memory_sidecar_proof_v1.zig");
const batch = @import("block_execution_sidecar_batch_v2.zig");
const trace_mod = @import("block_execution_sidecar_trace_v2.zig");
const seal_mod = @import("block_v5_source_seal_v1.zig");

test "block-v5 same-root opcode sidecar proves universal and global transition sums" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const instructions = [_]u32{ 0x00500093, 0x0000006f };
    const elf = @import("../runner/guest_precompile/test_elf.zig").buildProgram(instructions.len, &instructions, 0, .rv32im_zkvm_v1);
    var session = try runner.BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var segment = try session.startSegment(1);
    defer segment.deinit();
    var io = try public.Owned.init(a, &segment);
    defer io.deinit();
    var data = io.data;
    var memory = try custody.build(a, @as(@import("../air/program/commitment.zig").DeclaredDecodeAuthority, .base), .{segment.execution_trace.rows.items}, &segment.rw_memory, @import("commitment_program_witness.zig").completionFetch(data.completion), 100);
    defer memory.deinit();
    try memory.bindPublic(&data);
    io.data = data;
    var plan = try memory.plan(a);
    defer plan.deinit();
    const pin = try plan_mod.Admission.init(&plan, try plan.identity());
    const owner = try native_mod.Owner.init(a, &segment.execution_trace, data, &segment.state_chain_tracker);
    defer owner.deinit();
    try owner.sealNativeOnly();
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const Native = native_proof.ForBackend(Cpu);
    var native_first = try Native.commitFirstRound(a, owner, pin, config, .rv32im_zkvm_v1, 0);
    defer native_first.deinit(a);
    const frame = @import("../air/block/memory_event.zig").Frame{ .clock_frame = .leaf_local, .global_first_cycle = segment.global_first_cycle, .cycle_count = @intCast(segment.cycle_count) };
    const slots = try batch.slotsFromStatement(a, &owner.statement, frame);
    defer a.free(slots);
    const traces = try a.alloc(trace_mod.Trace, slots.len);
    defer a.free(traces);
    const inputs = try a.alloc(batch.Input, slots.len);
    defer a.free(inputs);
    var initialized: usize = 0;
    defer for (traces[0..initialized]) |*trace| trace.deinit();
    for (slots, inputs, 0..) |slot, *input, i| {
        var offset: usize = 0;
        var found: ?usize = null;
        for (owner.statement.component_descs[0..owner.statement.n_components], 0..) |desc, component| {
            if (offset == slot.main_offset and desc.family == slot.family) {
                found = component;
                break;
            }
            offset += desc.n_columns;
        }
        traces[i] = try trace_mod.Trace.init(a, slot.family, &owner.opcode_columns.components[found orelse return error.MissingV5OpcodeComponent], slot.slot, slot.log_size, slot.frame);
        initialized += 1;
        input.* = .{ .descriptor = slot, .trace = &traces[i] };
    }
    var counter = try @import("../air/lookups/tables/counter.zig").Counter.init(a, .range_check_8_8);
    defer counter.deinit(a);
    const Sidecar = sidecar.ForBackend(Cpu);
    var first = try Sidecar.commitFirstRound(a, owner.preprocessed.items, owner.main.items, inputs, slots, &counter, 0, native_first.template_id, config);
    defer first.deinit(a);
    try std.testing.expectEqualDeep(native_first.roots, first.roots[0..2].*);
    var counts: [seal_mod.family_count]u32 = @splat(0);
    counts[@intFromEnum(seal_mod.Family.program) - 1] = 1;
    counts[@intFromEnum(seal_mod.Family.execution) - 1] = 1;
    counts[@intFromEnum(seal_mod.Family.execution_sidecar) - 1] = 1;
    counts[@intFromEnum(seal_mod.Family.program_request) - 1] = 1;
    counts[@intFromEnum(seal_mod.Family.memory) - 1] = 1;
    const pins = seal_mod.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = native_first.template_id, .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .config = config, .counts = counts };
    const entries = [_]seal_mod.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(7), .roots = .{ @splat(8), @splat(9) } },
        native_first.entry(),
        sidecar.entry(native_first.instance_id, native_first.roots, first.roots[2], 0, slots),
        .{ .family = .program_request, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
        .{ .family = .memory, .index = 0, .instance_id = @splat(13), .roots = .{ @splat(14), @splat(15) } },
    };
    const sealed = try seal_mod.seal(pins, &entries);
    const native_received = try Native.prove(a, &native_first, sealed, pins, &entries);
    const native_receipt = try Native.verifyOwned(a, native_received, &owner.statement, pin, native_first.template, native_first.template_id, .rv32im_zkvm_v1, 0, sealed, pins, &entries);
    const received = try Sidecar.prove(a, &first, inputs, slots, sealed, pins, &entries, null, &native_receipt, 0, first.roots[2]);
    var verified = try Sidecar.verifyOwned(a, received, sealed, pins, &entries, null, &native_receipt, 0, slots, first.fixed_logs, first.main_logs, first.roots[2], config);
    defer verified.deinit(a);
    try std.testing.expect(verified.event_count > 0);
    try std.testing.expect(!verified.transition_sum.isZero());
    try std.testing.expect(!verified.universal_sum.isZero());
    const challenges = try @import("block_memory_relation_v2.zig").Challenges.draw(a, sealed);
    const elements = challenges.universal_prefix.get(.memory_access);
    var native_typed_sum = core.fields.qm31.QM31.zero();
    for (traces[0..initialized]) |*trace| for (0..trace.domainSize()) |logical| {
        const row = try @import("block_v5_opcode_memory_interaction_v1.zig").rowFromPair(try trace.pairAt(logical));
        if (!row.active) continue;
        native_typed_sum = native_typed_sum
            .sub(try (try elements.combineBase(&row.consumed)).inv())
            .add(try (try elements.combineBase(&row.emitted)).inv());
    };
    try std.testing.expect(native_typed_sum.add(verified.universal_sum).isZero());
    var changed = entries;
    changed[2].roots[0][0] ^= 1;
    try std.testing.expectError(error.UntrustedBlockV5SourceSeal, sealed.require(pins, &changed));
}
