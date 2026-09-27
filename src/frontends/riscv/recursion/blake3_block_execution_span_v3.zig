//! Block-v3 execution leaf binding. Span RW digests carry the independently
//! pinned initial-image anchor throughout the tree; native per-segment RW
//! roots live in the verified child/sidecar receipt. The separately verified
//! sidecar and global sorted-memory bus supply transition authority. A
//! complete-block receiver must fresh-verify all artifacts and close the bus.
const std = @import("std");
const core = @import("stwo_core");
const span = @import("span_statement_blake3.zig");
const io = @import("blake3_public_io.zig");
const public = @import("../air/public_data.zig");
const seal_mod = @import("../prover/block_memory_source_seal_v2.zig");
const sidecar_mod = @import("../prover/block_execution_sidecar_batch_v2.zig");
const parent = @import("blake3_execution_parent_preparation.zig");

pub const VERSION: u32 = 3;
const TAG: u32 = 0x42334553; // B3ES, distinct version from custody v2.

/// The initial-image root is an invariant bus anchor in this protocol. Native
/// per-segment ordinary RW roots are checked in their own proof receipts and
/// need not coincide at public-I/O boundaries.
pub fn initJobFromEndpoints(
    config: core.pcs.PcsConfig,
    first: @import("../prover/blake3_segment_statement.zig").Endpoint,
    last: @import("../prover/blake3_segment_statement.zig").Endpoint,
    segments: u32,
    pinned_initial_image_root: span.Digest,
) !span.JobContext {
    try @import("../prover/blake3_execution_protocol.zig").validateConfig(config);
    if (first.side != .entry or last.side != .exit or first.cycle != 0 or last.cycle == 0 or
        segments == 0 or segments > last.cycle or !std.meta.eql(first.program, last.program))
        return error.InvalidBlockExecutionEndpoints;
    if (!std.mem.allEqual(u8, &first.machine.public_io_state.bytes, 0) or
        !std.mem.allEqual(u8, &last.machine.public_io_state.bytes, 0))
        return error.InvalidBlockExecutionIoState;
    if (!std.meta.eql(first.machine.rw_memory, pinned_initial_image_root))
        return error.UntrustedBlockInitialImageRoot;
    const anchor = pinned_initial_image_root;
    const last_machine = try span.MachineState.init(
        last.machine.pc,
        last.machine.registers,
        anchor,
        .{ .bytes = @splat(0) },
    );
    return span.JobContext.init(try span.CompleteExecution.init(
        protocolIdentity(config),
        first.program,
        first.machine,
        last_machine,
        first.io,
        last.io,
        last.cycle,
    ), segments);
}

pub fn leaf(job: span.JobContext, segment: *const @import("../runner/result.zig").SegmentResult) !span.SpanStatement {
    try job.validate();
    try @import("../prover/blake3_segment_public.zig").validateSegment(segment);
    if (segment.segment_index >= job.segment_count or
        segment.segment_role.is_last != (segment.segment_index == job.segment_count - 1))
        return error.InvalidBlockExecutionLeaf;
    const anchor = job.complete.initial_state.rw_memory;
    if (!std.meta.eql(job.complete.final_state.rw_memory, anchor)) return error.InvalidBlockExecutionAnchor;
    const entry = try span.MachineState.init(segment.entry_cpu.pc, segment.entry_cpu.regs, anchor, .{ .bytes = @splat(0) });
    const exit = try span.MachineState.init(segment.exit_cpu.pc, segment.exit_cpu.regs, anchor, .{ .bytes = @splat(0) });
    return span.SpanStatement.segmentLeaf(job, segment.segment_index, try span.ExecutedSpan.init(
        segment.segment_index,
        1,
        segment.global_first_cycle - 1,
        segment.cycle_count,
        entry,
        exit,
        .{ .digest = if (segment.segment_role.is_first) job.complete.public_input else null },
        .{ .digest = if (segment.segment_role.is_last) job.complete.public_output else null },
    ));
}

pub fn protocolIdentity(config: core.pcs.PcsConfig) span.Digest {
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ TAG, VERSION, io.VERSION, seal_mod.FORMAT_VERSION });
    config.mixInto(&channel);
    return .{ .bytes = channel.digestBytes() };
}

pub fn bindingIdentity(statement: span.SpanStatement, child_key: [32]u8, receipt: *const sidecar_mod.VerifiedExecutionReceipt) ![32]u8 {
    const statement_id = (try span.identity.hash(&try statement.canonicalWords(), .statement)).bytes;
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ TAG, VERSION, receipt.instance_index });
    channel.mixRoot(child_key);
    channel.mixRoot(statement_id);
    for (receipt.native_roots) |root| channel.mixRoot(root);
    channel.mixRoot(receipt.witness_root);
    channel.mixRoot(receipt.sealed_channel_digest);
    channel.mixU64(receipt.event_count);
    for (receipt.transition_sum.toM31Array()) |limb| channel.mixU32s(&.{limb.toU32()});
    channel.mixU32s(&.{@intCast(receipt.range_claims.len)});
    for (receipt.range_claims) |batch| for (batch) |claim| {
        for (claim.toM31Array()) |limb| channel.mixU32s(&.{limb.toU32()});
    };
    return channel.digestBytes();
}

pub fn validate(
    statement: span.SpanStatement,
    data: *const public.Blake3PublicData,
    config: core.pcs.PcsConfig,
    seal: seal_mod.SourceSeal,
    expected: [32]u8,
    native_roots: [2][32]u8,
    expected_witness_root: [32]u8,
    receipt: *const sidecar_mod.VerifiedExecutionReceipt,
) !void {
    try statement.validate();
    try data.validate();
    if (!seal.bound_rosters or statement.body != .executed or statement.slots.height != 0) return error.InvalidBlockExecutionLeaf;
    const executed = statement.body.executed;
    if (executed.segment_count != 1 or statement.slots.first != executed.first_segment or
        executed.first_segment >= seal.execution_instance_count or receipt.instance_index != executed.first_segment or
        executed.cycle_count != data.clock or executed.entry.pc != data.initial_pc or executed.exit.pc != data.final_pc or
        !std.meta.eql(executed.entry.registers, data.initial_regs) or !std.meta.eql(executed.exit.registers, data.final_regs) or
        !std.meta.eql(executed.entry.rw_memory, statement.job.complete.initial_state.rw_memory) or
        !std.meta.eql(executed.exit.rw_memory, statement.job.complete.initial_state.rw_memory) or
        !std.meta.eql(statement.job.complete.final_state.rw_memory, statement.job.complete.initial_state.rw_memory) or
        !std.meta.eql(statement.job.complete.program, data.program_root.?) or
        !std.meta.eql(statement.job.complete.protocol_id, protocolIdentity(config))) return error.InvalidBlockExecutionLeaf;
    if (!std.mem.allEqual(u8, &executed.entry.public_io_state.bytes, 0) or
        !std.mem.allEqual(u8, &executed.exit.public_io_state.bytes, 0)) return error.InvalidBlockExecutionIoState;
    if (executed.first_segment == 0) {
        if (!std.meta.eql(executed.input.digest.?, try io.input(data))) return error.InvalidBlockExecutionInput;
    } else if (data.io_entries.input_words.len != 0 or data.io_entries.input_len != 0) return error.InteriorBlockExecutionInput;
    if (executed.endSegment() == statement.job.segment_count) {
        if (data.completion.?.kind == .unretired_program_fetch) return error.IncompleteBlockExecution;
        if (!std.meta.eql(executed.output.digest.?, try io.output(data))) return error.InvalidBlockExecutionOutput;
    } else if (data.io_entries.output_words.len != 0 or data.io_entries.output_len != 0 or
        data.completion.?.kind == .halt_flag) return error.InteriorBlockExecutionOutput;
    var shared = seal.sharedChannel();
    if (!std.meta.eql(receipt.native_roots, native_roots) or
        !std.meta.eql(receipt.witness_root, expected_witness_root) or
        !std.mem.eql(u8, &receipt.native_key_id, &expected) or
        !std.mem.eql(u8, &receipt.sealed_channel_digest, &shared.digestBytes())) return error.UntrustedBlockExecutionSidecar;
}

/// Metadata attachment only. The complete-block receiver supplies authority by
/// independently verifying the native and sidecar proof bytes and their sums.
pub fn attach(
    result: *parent.Prepared,
    admitted: anytype,
    capture: anytype,
    expected: [32]u8,
    statement: span.SpanStatement,
    seal: seal_mod.SourceSeal,
    expected_witness_root: [32]u8,
    receipt: *const sidecar_mod.VerifiedExecutionReceipt,
) !void {
    try preflight(admitted, capture, expected, statement, seal, expected_witness_root, receipt);
    try attachValidated(result, expected, statement, receipt);
}

fn preflight(
    admitted: anytype,
    capture: anytype,
    expected: [32]u8,
    statement: span.SpanStatement,
    seal: seal_mod.SourceSeal,
    expected_witness_root: [32]u8,
    receipt: *const sidecar_mod.VerifiedExecutionReceipt,
) !void {
    try capture.validate(admitted, expected);
    const roots = capture.proof.commitments;
    if (roots.len < 2) return error.InvalidBlockExecutionCapture;
    const data = if (comptime @hasField(@TypeOf(admitted.*), "native"))
        &admitted.native.public_data
    else
        &admitted.shape.public_data;
    try validate(statement, data, admitted.config, seal, expected, roots[0..2].*, expected_witness_root, receipt);
}

fn attachValidated(result: *parent.Prepared, expected: [32]u8, statement: span.SpanStatement, receipt: *const sidecar_mod.VerifiedExecutionReceipt) !void {
    if (!std.mem.eql(u8, &result.context.child_key_id, &expected) or
        result.context.statement_identity != null or result.context.span_binding_id != null) return error.InvalidBlockParentAttachment;
    const statement_id = (try span.identity.hash(&try statement.canonicalWords(), .statement)).bytes;
    const binding_id = try bindingIdentity(statement, expected, receipt);
    result.context.statement_identity = statement_id;
    result.context.span_binding_id = binding_id;
}

/// Build only the native child-verifier rows. The execution access sidecar is
/// checked by the batch receiver, so there are no per-leaf custody-conversion
/// rows in this versioned path.
pub fn prepare(
    a: std.mem.Allocator,
    admitted: anytype,
    capture: anytype,
    expected: [32]u8,
    capacity: u32,
    statement: span.SpanStatement,
    seal: seal_mod.SourceSeal,
    expected_witness_root: [32]u8,
    receipt: *const sidecar_mod.VerifiedExecutionReceipt,
) !parent.Prepared {
    try preflight(admitted, capture, expected, statement, seal, expected_witness_root, receipt);
    var result = try parent.prepare(a, admitted, capture, expected, capacity);
    errdefer result.deinit();
    try attachValidated(&result, expected, statement, receipt);
    return result;
}

pub fn prepareBounded(
    a: std.mem.Allocator,
    admitted: anytype,
    capture: anytype,
    expected: [32]u8,
    capacity: u32,
    byte_limit: usize,
    statement: span.SpanStatement,
    seal: seal_mod.SourceSeal,
    expected_witness_root: [32]u8,
    receipt: *const sidecar_mod.VerifiedExecutionReceipt,
) !parent.Prepared {
    try preflight(admitted, capture, expected, statement, seal, expected_witness_root, receipt);
    var result = try parent.prepareBounded(a, admitted, capture, expected, capacity, byte_limit);
    errdefer result.deinit();
    try attachValidated(&result, expected, statement, receipt);
    return result;
}

test "block-v3 execution protocol identity is versioned and configuration-bound" {
    const config = core.pcs.PcsConfig{ .pow_bits = 26, .fri_config = .{ .log_blowup_factor = 2, .log_last_layer_degree_bound = 0, .n_queries = 70, .fold_step = 1 } };
    const diagnostic = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 8, .fold_step = 1 } };
    try std.testing.expect(!std.meta.eql(protocolIdentity(config), protocolIdentity(diagnostic)));
    try std.testing.expect(!std.meta.eql(protocolIdentity(config), @import("blake3_execution_span.zig").protocolIdentity(config)));
}

test "block-v3 job carries one initial-image anchor across native boundaries" {
    const Endpoint = @import("../prover/blake3_segment_statement.zig").Endpoint;
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 8, .fold_step = 1 } };
    const registers: [32]u32 = @splat(0);
    const initial = try span.MachineState.init(4, registers, .{ .bytes = @splat(1) }, .{ .bytes = @splat(0) });
    const final = try span.MachineState.init(8, registers, .{ .bytes = @splat(2) }, .{ .bytes = @splat(0) });
    const first = Endpoint{ .machine = initial, .program = .{ .bytes = @splat(3) }, .io = .{ .bytes = @splat(4) }, .cycle = 0, .side = .entry };
    const last = Endpoint{ .machine = final, .program = first.program, .io = .{ .bytes = @splat(5) }, .cycle = 10, .side = .exit };
    const job = try initJobFromEndpoints(config, first, last, 2, initial.rw_memory);
    try std.testing.expectError(error.UntrustedBlockInitialImageRoot, initJobFromEndpoints(config, first, last, 2, final.rw_memory));
    try std.testing.expectEqualDeep(job.complete.initial_state.rw_memory, job.complete.final_state.rw_memory);
    try std.testing.expectEqualDeep(initial.rw_memory, job.complete.initial_state.rw_memory);
    try std.testing.expectEqualDeep(final.pc, job.complete.final_state.pc);
    try std.testing.expectEqualDeep(protocolIdentity(config), job.complete.protocol_id);
}
