const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const Column = engine.pcs.ColumnEvaluation;
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const opcode = @import("../runner/trace.zig");
const trace_mod = @import("block_execution_sidecar_trace_v2.zig");
const sidecar_mod = @import("block_execution_sidecar_proof_v2.zig");
const table_mod = @import("block_memory_shared_table_proof_v2.zig");
const shard_mod = @import("block_memory_range_shard_v2.zig");
const seal_mod = @import("block_memory_source_seal_v2.zig");

test "block-v2 native-root execution sidecar matches freshly verified typed proof" {
    const a = std.testing.allocator;
    const instructions = [_]u32{ 0x00500093, 0x00708093, 0x00100137, 0x00100193, 0x00312223, 0x00312423, 0x0000006f };
    const elf = @import("../runner/guest_precompile/test_elf.zig").buildReleaseProgram(instructions.len, &instructions, 0, .rv32im_zkvm_v1);
    var run = try @import("../runner/mod.zig").runWithInput(a, &elf, &.{}, 100);
    defer run.deinit();
    var owner = try @import("blake3_segment_execution.zig").Owner.initCompactRun(a, &run);
    defer owner.deinit();
    const native = owner.native;
    const family: opcode.OpcodeFamily = .base_alu_imm;
    var component_index: ?usize = null;
    var main_offset: usize = 0;
    for (native.statement.component_descs[0..native.statement.n_components], 0..) |desc, index| {
        if (desc.family == family) { component_index = index; break; }
        main_offset += desc.n_columns;
    }
    const index = component_index orelse return error.MissingAddiComponent;
    const descriptor = native.statement.component_descs[index];
    var sidecar_trace = try trace_mod.Trace.init(a, family, &native.opcode_columns.components[index], 0, descriptor.log_size, .{
        .clock_frame = .leaf_local, .global_first_cycle = 1,
        .cycle_count = @intCast(run.execution_trace.rows.items.len),
    });
    defer sidecar_trace.deinit();
    const pin = try owner.admission();
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const native_api = @import("blake3_execution_proof.zig").ForBackend(Cpu);
    const prepared = try native_api.PreparedVerifier.initCompact(a, &native.statement, pin, config, native.compact_ranges.?.plan);
    defer prepared.deinit();

    var scratch = std.heap.ArenaAllocator.init(a);
    defer scratch.deinit();
    var fixed: std.ArrayList(Column) = .empty;
    try fixed.appendSlice(scratch.allocator(), native.preprocessed.items);
    try fixed.appendSlice(scratch.allocator(), owner.hashes.preprocessed());
    var main: std.ArrayList(Column) = .empty;
    try main.appendSlice(scratch.allocator(), native.main.items);
    try main.appendSlice(scratch.allocator(), &native.compact_ranges.?.columns);
    try main.appendSlice(scratch.allocator(), try owner.hashes.main());
    var counter = try @import("../air/lookups/tables/counter.zig").Counter.init(a, .range_check_8_8);
    defer counter.deinit(a);
    const sidecar_api = sidecar_mod.ForBackend(Cpu);
    var first = try sidecar_api.commitFirstRound(a, fixed.items, main.items, &sidecar_trace, main_offset, &counter, 0, config);
    defer first.deinit(a);
    const native_roots: [2]suite.Hasher.Hash = first.roots[0..2].*;
    const shard = shard_mod.Shard{ .index = 0, .first_instance = 0, .instance_count = 1, .first_event = 0, .event_count = descriptor.n_rows, .max_requests = @as(u64, descriptor.n_rows) * 35 };
    const table_api = table_mod.ForBackend(Cpu);
    var table_first = try table_api.commitFirstRound(a, &counter, shard, config);
    defer table_first.deinit(a);

    const proved = try native_api.proveCompact(a, native, owner.hashes, pin, config);
    const native_artifact = try @import("blake3_execution_codec.zig").encode(a, &proved.proof, prepared, prepared.id);
    defer a.free(native_artifact);
    const native_stark_roots = proved.proof.stark.commitment_scheme_proof.commitments.items;
    try std.testing.expectEqualDeep(native_roots, native_stark_roots[0..2].*);
    var captured = try native_api.verifyPreparedCaptureOwned(a, proved.proof, prepared, prepared.id);
    defer captured.deinit();
    try captured.validate(prepared, prepared.id);
    try std.testing.expectEqualDeep(native_roots, captured.proof.commitments[0..2].*);

    const entries = [_]seal_mod.FirstRoundEntry{
        .{ .family = .execution, .index = 0, .roots = native_roots },
        .{ .family = .execution_sidecar_witness, .index = 0, .roots = .{ first.roots[2], @splat(0) } },
        .{ .family = .range_table, .index = 0, .roots = table_first.roots },
    };
    const base = @import("block_commitment_manifest.zig").Sealed{ .digest = @splat(97), .instance_count = 1 };
    const sealed = try seal_mod.SourceSeal.initBound(base, 0, @splat(98), 1, 1, shard_mod.digestRoster(&.{shard}, descriptor.n_rows, 1), seal_mod.digestFirstRoundRoster(&entries));
    const sidecar = try sidecar_api.prove(a, &first, &sidecar_trace, sealed, 0, main_offset, native_roots, first.roots[2]);
    const table = try table_api.prove(a, &table_first, &counter, shard, sealed, table_first.roots);
    const receipt = try sidecar_api.verifyOwned(a, sidecar, sealed, 0, family, 0, descriptor.log_size, sidecar_trace.frame, main_offset, first.fixed_logs, first.main_logs, captured.proof.commitments[0..2].*, first.roots[2], config);
    const table_receipt = try table_api.verifyOwned(a, table, shard, sealed, table_first.roots, config);
    var total = table_receipt.claim;
    for (receipt.range_claims) |claim| total = total.add(claim);
    try std.testing.expect(total.isZero());
    try std.testing.expect(!receipt.transition_sum.isZero());

    // Enumerate every access slot from the freshly verified typed statement
    // and prove all of them against the same native root pair in one STARK.
    // The native prover consumes its input columns, so rebuild the public
    // execution witness for this second, independently committed proof.
    var batch_owner = try @import("blake3_segment_execution.zig").Owner.initCompactRun(a, &run);
    defer batch_owner.deinit();
    const batch_native = batch_owner.native;
    var batch_fixed: std.ArrayList(Column) = .empty;
    try batch_fixed.appendSlice(scratch.allocator(), batch_native.preprocessed.items);
    try batch_fixed.appendSlice(scratch.allocator(), batch_owner.hashes.preprocessed());
    var batch_main: std.ArrayList(Column) = .empty;
    try batch_main.appendSlice(scratch.allocator(), batch_native.main.items);
    try batch_main.appendSlice(scratch.allocator(), &batch_native.compact_ranges.?.columns);
    try batch_main.appendSlice(scratch.allocator(), try batch_owner.hashes.main());
    const batch_mod = @import("block_execution_sidecar_batch_v2.zig");
    const slots = try batch_mod.slotsFromStatement(a, &batch_native.statement, sidecar_trace.frame);
    defer a.free(slots);
    const traces = try a.alloc(trace_mod.Trace, slots.len);
    defer a.free(traces);
    const inputs = try a.alloc(batch_mod.Input, slots.len);
    defer a.free(inputs);
    var initialized: usize = 0;
    defer for (traces[0..initialized]) |*item| item.deinit();
    var batch_events: u64 = 0;
    for (slots, inputs, 0..) |slot, *input, slot_index| {
        var component_offset: usize = 0;
        var found: ?usize = null;
        for (batch_native.statement.component_descs[0..batch_native.statement.n_components], 0..) |desc, component| {
            if (component_offset == slot.main_offset and desc.family == slot.family) { found = component; break; }
            component_offset += desc.n_columns;
        }
        const component = found orelse return error.MissingExecutionSlotComponent;
        traces[slot_index] = try trace_mod.Trace.init(a, slot.family, &batch_native.opcode_columns.components[component], slot.slot, slot.log_size, slot.frame);
        initialized += 1;
        input.* = .{ .descriptor = slot, .trace = &traces[slot_index] };
        for (0..traces[slot_index].domainSize()) |logical| batch_events += @intFromBool((try traces[slot_index].row(logical)).active);
    }
    try std.testing.expect(batch_events > 1);
    var batch_counter = try @import("../air/lookups/tables/counter.zig").Counter.init(a, .range_check_8_8);
    defer batch_counter.deinit(a);
    const batch_api = batch_mod.ForBackend(Cpu);
    var batch_first = try batch_api.commitFirstRound(a, batch_fixed.items, batch_main.items, inputs, slots, &batch_counter, 0, captured.key_id, config);
    defer batch_first.deinit(a);
    try std.testing.expectEqualDeep(native_roots, batch_first.roots[0..2].*);
    const batch_shard = shard_mod.Shard{ .index = 0, .first_instance = 0, .instance_count = 1, .first_event = 0, .event_count = batch_events, .max_requests = batch_events * 35 };
    var batch_table_first = try table_api.commitFirstRound(a, &batch_counter, batch_shard, config);
    defer batch_table_first.deinit(a);
    const batch_entries = [_]seal_mod.FirstRoundEntry{
        .{ .family = .execution, .index = 0, .roots = native_roots },
        .{ .family = .execution_sidecar_witness, .index = 0, .roots = .{ batch_first.roots[2], @splat(0) } },
        .{ .family = .range_table, .index = 0, .roots = batch_table_first.roots },
    };
    const batch_sealed = try seal_mod.SourceSeal.initBound(base, 0, @splat(99), 1, 1, shard_mod.digestRoster(&.{batch_shard}, batch_events, 1), seal_mod.digestFirstRoundRoster(&batch_entries));
    const batch_proof = try batch_api.prove(a, &batch_first, inputs, slots, batch_sealed, 0, captured.key_id, native_roots, batch_first.roots[2]);
    var sidecar_writer = std.Io.Writer.Allocating.init(a);
    defer sidecar_writer.deinit();
    try @import("interop_postcard").serializeProof(suite.Hasher, &sidecar_writer.writer, batch_proof.stark);
    const sidecar_bytes = try a.dupe(u8, sidecar_writer.written());
    defer a.free(sidecar_bytes);
    const sidecar_claims = try a.dupe(batch_mod.Claim, batch_proof.claims);
    defer a.free(sidecar_claims);
    const batch_table_proof = try table_api.prove(a, &batch_table_first, &batch_counter, batch_shard, batch_sealed, batch_table_first.roots);
    var batch_receipt = try batch_api.verifyOwned(a, batch_proof, batch_sealed, 0, captured.key_id, slots, batch_first.fixed_logs, batch_first.main_logs, captured.proof.commitments[0..2].*, batch_first.roots[2], config);
    defer batch_receipt.deinit(a);
    const batch_table_receipt = try table_api.verifyOwned(a, batch_table_proof, batch_shard, batch_sealed, batch_table_first.roots, config);
    try std.testing.expectEqual(batch_events, batch_receipt.event_count);
    var batch_range_total = batch_table_receipt.claim;
    for (batch_receipt.range_claims) |claims| for (claims) |claim| { batch_range_total = batch_range_total.add(claim); };
    try std.testing.expect(batch_range_total.isZero());

    const span = @import("../recursion/span_statement_blake3.zig");
    const v3 = @import("../recursion/blake3_block_execution_span_v3.zig");
    const io = @import("../recursion/blake3_public_io.zig");
    const data = &batch_native.statement.public_data;
    const entry = try span.MachineState.init(data.initial_pc, data.initial_regs, data.initial_rw_root.?, .{ .bytes = @splat(0) });
    const exit_state = try span.MachineState.init(data.final_pc, data.final_regs, data.initial_rw_root.?, .{ .bytes = @splat(0) });
    const input_digest = try io.input(data);
    const output_digest = try io.output(data);
    const complete = try span.CompleteExecution.init(v3.protocolIdentity(config), data.program_root.?, entry, exit_state, input_digest, output_digest, data.clock);
    const job = try span.JobContext.init(complete, 1);
    const executed = try span.ExecutedSpan.init(0, 1, 0, data.clock, entry, exit_state, .{ .digest = input_digest }, .{ .digest = output_digest });
    const statement = try span.SpanStatement.segmentLeaf(job, 0, executed);
    try v3.validate(statement, data, config, batch_sealed, captured.key_id, captured.proof.commitments[0..2].*, batch_first.roots[2], &batch_receipt);
    const receiver = @import("block_execution_batch_receiver_v2.zig").ForBackend(Cpu);
    var receiver_receipt = try receiver.verify(a, .{
        .native_artifact = native_artifact, .sidecar_stark = sidecar_bytes, .sidecar_claims = sidecar_claims,
    }, prepared, prepared.id, statement, batch_sealed, 0, batch_first.roots[2], config);
    defer receiver_receipt.deinit(a);
    try std.testing.expectEqualDeep(batch_receipt.native_roots, receiver_receipt.native_roots);
    try std.testing.expectEqual(batch_events, receiver_receipt.event_count);
    var forged_receipt = batch_receipt;
    forged_receipt.witness_root[0] ^= 1;
    try std.testing.expectError(error.UntrustedBlockExecutionSidecar, v3.validate(statement, data, config, batch_sealed, captured.key_id, captured.proof.commitments[0..2].*, batch_first.roots[2], &forged_receipt));
}
