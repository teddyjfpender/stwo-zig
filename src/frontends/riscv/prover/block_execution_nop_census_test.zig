//! Genuine ADDI x0,x0,0 rows must close the runner-to-typed access census.
const std = @import("std");
const runner = @import("../runner/mod.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Native = @import("blake3_ethereum_sha_proof.zig").ForBackend(Cpu);
const Artifact = @import("block_execution_sha_artifact_v2.zig").ForBackend(Cpu);
const sidecar = @import("block_execution_sidecar_batch_v2.zig");
const sidecar_trace = @import("block_execution_sidecar_trace_v2.zig");
const event = @import("../air/block/memory_event.zig");

test "genuine NOP register accesses close the typed sidecar census" {
    const a = std.testing.allocator;
    const fixture = @import("../runner/guest_precompile/test_elf.zig");
    var program = fixture.buildEthereumSha(.rv32im_zkvm_ethereum_sha_v1);
    for (3..6) |instruction| {
        std.mem.writeInt(
            u32,
            program[640 + instruction * 4 ..][0..4],
            0x0000_0013,
            .little,
        );
    }
    const elf = fixture.withReleaseAbi(program.len, &program);
    var session = try runner.EthereumShaExecutionSession.init(
        a,
        &elf,
        .{ .clock_frame = .leaf_local, .trace_retention = .segment_owned },
    );
    defer session.deinit();
    var segment = try session.startSegment(7);
    defer segment.deinit();
    try std.testing.expect(segment.base.isComplete());
    var owner = try Profile.Witness.initCompactSegment(a, &segment);
    defer owner.deinit();
    const native = owner.native;
    const frame = event.Frame{
        .clock_frame = .leaf_local,
        .global_first_cycle = segment.base.global_first_cycle,
        .cycle_count = @intCast(segment.base.cycle_count),
    };
    const config = @import("../recursion/blake3_execution_parent_protocol.zig").PCS_CONFIG;
    const prepared = try Native.PreparedVerifier.initCompact(
        a,
        &native.statement,
        owner.statement,
        try owner.admission(),
        config,
        native.compact_ranges.?.plan,
    );
    defer prepared.deinit();
    var artifact = try Artifact.init(a, &owner, prepared, frame, 0, config);
    defer artifact.deinit();
    const slots = try sidecar.slotsFromStatement(a, &native.statement, frame);
    defer a.free(slots);
    var typed_count: usize = 0;
    var addi_pairs: usize = 0;
    for (slots) |slot| {
        var offset: usize = 0;
        var source_index: ?usize = null;
        for (native.statement.component_descs[0..native.statement.n_components], 0..) |desc, i| {
            if (offset == slot.main_offset and desc.family == slot.family) {
                source_index = i;
                break;
            }
            offset += desc.n_columns;
        }
        var trace = try sidecar_trace.Trace.init(
            a,
            slot.family,
            &native.opcode_columns.components[source_index orelse return error.MissingOpcodeComponent],
            slot.slot,
            slot.log_size,
            frame,
        );
        defer trace.deinit();
        for (0..trace.domainSize()) |logical| {
            if ((try trace.row(logical)).active) {
                typed_count += 1;
                if (slot.family == .base_alu_imm) addi_pairs += 1;
            }
        }
    }
    var nop_rows: usize = 0;
    for (segment.base.execution_trace.rows.items) |row| {
        if (row.opcode == .ADDI and row.rd == 0 and row.rs1 == 0 and row.imm == 0)
            nop_rows += 1;
    }
    std.debug.print(
        "NOP_CENSUS runner={d} typed={d} artifact={d} trace_rows={d} nop_rows={d} addi_pairs={d}\n",
        .{ segment.base.state_chain_tracker.accesses.items.len, typed_count, artifact.event_count, segment.base.execution_trace.rows.items.len, nop_rows, addi_pairs },
    );
    try std.testing.expectEqual(@as(usize, 3), nop_rows);
    try std.testing.expectEqual(
        segment.base.state_chain_tracker.accesses.items.len,
        typed_count,
    );
    try std.testing.expectEqual(@as(u64, @intCast(typed_count)), artifact.event_count);

    // Compare the complete event multiset, not just its length: each x0 NOP
    // must retain both architectural register transitions at the same clocks.
    var runner_events: std.ArrayList(event.Event) = .empty;
    defer runner_events.deinit(a);
    for (segment.base.state_chain_tracker.accesses.items) |access| {
        try runner_events.append(a, try frame.project(access));
    }
    var sidecar_events: std.ArrayList(event.Event) = .empty;
    defer sidecar_events.deinit(a);
    for (artifact.traces) |*trace| {
        for (0..trace.domainSize()) |logical| {
            const row = try trace.row(logical);
            if (!row.active) continue;
            const decoded = try @import("block_memory_relation_v2.zig").decodeTransitionTuple(row.tuple);
            try sidecar_events.append(a, .{
                .space = decoded.space,
                .address = decoded.address,
                .clock = decoded.clock,
                .value = decoded.after,
            });
        }
    }
    std.mem.sort(event.Event, runner_events.items, {}, event.Event.lessThan);
    std.mem.sort(event.Event, sidecar_events.items, {}, event.Event.lessThan);
    try std.testing.expectEqualDeep(runner_events.items, sidecar_events.items);
}
