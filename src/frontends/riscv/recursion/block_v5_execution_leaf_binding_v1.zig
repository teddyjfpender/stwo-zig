//! Provisional block-v5 leaf statement binding. This checks the public span
//! against freshly verified native and same-root opcode sidecar receipts and
//! commits their open claims. `prepare` adds the native-v5 recursive verifier
//! rows; the opcode sidecar remains separately freshly verified. No complete
//! execution authority exists until global program, memory, precompile and
//! boundary providers close the B5SS relation bundle.
const std = @import("std");
const core = @import("stwo_core");
const span = @import("span_statement_blake3.zig");
const io = @import("blake3_public_io.zig");
const public = @import("../air/public_data.zig");
const seal_mod = @import("../prover/block_v5_source_seal_v1.zig");
const catalog_mod = @import("../prover/block_v5_native_template_catalog_v1.zig");
const template_mod = @import("../prover/block_v5_native_template_protocol.zig");
const native_mod = @import("../prover/block_v5_native_execution_proof_v1.zig");
const sidecar_mod = @import("../prover/block_v5_opcode_memory_sidecar_proof_v1.zig");
const recursive_admission = @import("../prover/block_v5_native_recursive_admission_v1.zig");
const parent = @import("blake3_execution_parent_proof.zig");

pub const VERSION: u32 = 1;
pub const TAG: u32 = 0x42354c42; // B5LB

pub fn protocolIdentity(config: core.pcs.PcsConfig) span.Digest {
    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ TAG, VERSION, seal_mod.VERSION, io.VERSION });
    config.mixInto(&channel);
    return .{ .bytes = channel.digestBytes() };
}

pub fn initJobFromEndpoints(config: core.pcs.PcsConfig, first: @import("../prover/blake3_segment_statement.zig").Endpoint, last: @import("../prover/blake3_segment_statement.zig").Endpoint, segments: u32, pinned_initial_image_root: span.Digest) !span.JobContext {
    var job = try @import("blake3_block_execution_span_v3.zig").initJobFromEndpoints(config, first, last, segments, pinned_initial_image_root);
    job.complete.protocol_id = protocolIdentity(config);
    try job.validate();
    return job;
}

pub fn leaf(config: core.pcs.PcsConfig, job: span.JobContext, segment: *const @import("../runner/result.zig").SegmentResult) !span.SpanStatement {
    if (!std.meta.eql(job.complete.protocol_id, protocolIdentity(config))) return error.InvalidBlockV5LeafProtocol;
    return @import("blake3_block_execution_span_v3.zig").leaf(job, segment);
}

/// A domain-separated input for a future v5 recursive verifier circuit. The
/// complete receiver must construct both receipts privately after fresh proof
/// verification and may use this value only while global closure is pending.
pub fn provisionalIdentity(
    statement: span.SpanStatement,
    data: *const public.Blake3PublicData,
    config: core.pcs.PcsConfig,
    sealed: seal_mod.Sealed,
    pins: seal_mod.Pins,
    entries: []const seal_mod.Entry,
    catalog: catalog_mod.Admission,
    template: template_mod.Template,
    native: *const native_mod.OpenReceipt,
    sidecar: *const sidecar_mod.Verified,
) ![32]u8 {
    try sealed.require(pins, entries);
    try statement.validate();
    try data.validate();
    if (statement.body != .executed or statement.slots.height != 0)
        return error.InvalidBlockV5LeafSpan;
    const executed = statement.body.executed;
    if (executed.segment_count != 1 or
        statement.job.segment_count != sealed.execution_instance_count or
        statement.slots.first != executed.first_segment or
        executed.first_segment >= sealed.execution_instance_count or
        executed.first_segment != sidecar.instance_index or
        executed.cycle_count != data.clock or
        executed.entry.pc != data.initial_pc or executed.exit.pc != data.final_pc or
        !std.meta.eql(executed.entry.registers, data.initial_regs) or
        !std.meta.eql(executed.exit.registers, data.final_regs) or
        !std.meta.eql(executed.entry.rw_memory, statement.job.complete.initial_state.rw_memory) or
        !std.meta.eql(executed.exit.rw_memory, statement.job.complete.initial_state.rw_memory) or
        !std.meta.eql(statement.job.complete.final_state.rw_memory, statement.job.complete.initial_state.rw_memory) or
        !std.meta.eql(statement.job.complete.program, data.program_root.?) or
        !std.meta.eql(statement.job.complete.protocol_id, protocolIdentity(config)))
        return error.InvalidBlockV5LeafSpan;
    if (!std.mem.allEqual(u8, &executed.entry.public_io_state.bytes, 0) or
        !std.mem.allEqual(u8, &executed.exit.public_io_state.bytes, 0))
        return error.InvalidBlockV5LeafIoState;
    if (executed.first_segment == 0) {
        if (!std.meta.eql(executed.input.digest.?, try io.input(data)))
            return error.InvalidBlockV5LeafInput;
    } else if (data.io_entries.input_words.len != 0 or data.io_entries.input_len != 0)
        return error.InteriorBlockV5LeafInput;
    if (executed.endSegment() == statement.job.segment_count) {
        if (data.completion.?.kind == .unretired_program_fetch or
            !std.meta.eql(executed.output.digest.?, try io.output(data)))
            return error.InvalidBlockV5LeafOutput;
    } else if (data.io_entries.output_words.len != 0 or data.io_entries.output_len != 0 or
        data.completion.?.kind == .halt_flag)
        return error.InteriorBlockV5LeafOutput;

    try catalog.admit(pins, sealed, executed.first_segment, template, native.template_id);
    if (!std.meta.eql(template.config, config) or
        !std.meta.eql(native.sealed_digest, sealed.digest) or
        !std.meta.eql(sidecar.sealed_digest, sealed.digest) or
        !std.meta.eql(native.first_roots, sidecar.native_roots) or
        !std.meta.eql(native.instance_id, sidecar.native_instance_id) or
        std.mem.allEqual(u8, &sidecar.witness_root, 0))
        return error.UntrustedBlockV5LeafReceipts;
    var found_native = false;
    for (entries) |entry| if (entry.family == .execution and entry.index == executed.first_segment) {
        if (!std.meta.eql(entry.roots, native.first_roots) or !std.meta.eql(entry.instance_id, native.instance_id))
            return error.UntrustedBlockV5LeafReceipts;
        found_native = true;
        break;
    };
    if (!found_native) return error.UntrustedBlockV5LeafReceipts;

    var channel = core.channel.blake3.Channel{};
    channel.mixU32s(&.{ TAG, VERSION, executed.first_segment });
    channel.mixRoot(sealed.digest);
    channel.mixRoot(pins.native_template_catalog_digest);
    channel.mixRoot(native.template_id);
    channel.mixRoot(native.instance_id);
    channel.mixRoot(native.first_roots[0]);
    channel.mixRoot(native.first_roots[1]);
    channel.mixRoot(sidecar.witness_root);
    channel.mixRoot((try span.identity.hash(&try statement.canonicalWords(), .statement)).bytes);
    data.mixInto(&channel);
    channel.mixFelts(&.{ native.open_sum, sidecar.universal_sum, sidecar.transition_sum });
    channel.mixU64(sidecar.event_count);
    channel.mixU32s(&.{@intCast(sidecar.range_claims.len)});
    for (sidecar.range_claims) |claims| channel.mixFelts(&claims);
    return channel.digestBytes();
}

/// Build the native-v5 verifier equations and attach the public v5 span and
/// open-claim binding. The sidecar remains a separately fresh verified proof;
/// this preparation grants no global relation closure.
pub fn prepare(
    a: std.mem.Allocator,
    admitted: *const recursive_admission.Prepared,
    capture: *const native_mod.VerifiedCapture,
    statement: span.SpanStatement,
    sidecar: *const sidecar_mod.Verified,
    capacity: u32,
) !parent.preparation.Prepared {
    try capture.validate(admitted, admitted.expected_id);
    const binding = try provisionalIdentity(statement, &admitted.shape.public_data, admitted.config,
        admitted.sealed, admitted.pins, admitted.entries,
        admitted.catalog orelse return error.MissingBlockV5LeafCatalog,
        admitted.template, &capture.receipt, sidecar);
    var result = try parent.preparation.prepare(a, admitted, capture, admitted.expected_id, capacity);
    errdefer result.deinit();
    if (result.context.statement_identity != null or result.context.span_binding_id != null)
        return error.InvalidBlockV5LeafAttachment;
    result.context.statement_identity = (try span.identity.hash(&try statement.canonicalWords(), .statement)).bytes;
    result.context.span_binding_id = binding;
    return result;
}

/// Fresh recursive leaf verification under an independent parent key pin.
/// Complete block authority still requires the receiver to fresh-verify all
/// provider proofs and cancel the exported open claims before admitting the
/// returned descriptor to its exact forest.
pub fn verifyLeafBytes(
    a: std.mem.Allocator,
    bytes: []const u8,
    admission: parent.protocol.Admission,
    expected_leaf_key_id: [32]u8,
    admitted: *const recursive_admission.Prepared,
    native: *const native_mod.OpenReceipt,
    sidecar: *const sidecar_mod.Verified,
    statement: span.SpanStatement,
) !@import("blake3_exact_root_receiver_v3.zig").Descriptor {
    try admission.validate();
    if (!std.meta.eql(admission.expected_id, expected_leaf_key_id))
        return error.UnlinkedBlockV5RecursiveLeaf;
    try admitted.validate(admitted.expected_id);
    const binding = try provisionalIdentity(statement, &admitted.shape.public_data, admitted.config,
        admitted.sealed, admitted.pins, admitted.entries,
        admitted.catalog orelse return error.MissingBlockV5LeafCatalog,
        admitted.template, native, sidecar);
    const statement_id = (try span.identity.hash(&try statement.canonicalWords(), .statement)).bytes;
    const context = admission.key.context;
    if (!std.meta.eql(admission.expected_id, expected_leaf_key_id) or
        !std.meta.eql(admission.key.config, admitted.config) or
        !std.meta.eql(context.child_config, admitted.config) or
        !std.meta.eql(context.child_key_id, admitted.expected_id) or
        context.statement_identity == null or context.span_binding_id == null or
        !std.meta.eql(context.statement_identity.?, statement_id) or
        !std.meta.eql(context.span_binding_id.?, binding) or
        context.aggregation != null or context.exact_aggregation != null or context.quad_aggregation != null)
        return error.UnlinkedBlockV5RecursiveLeaf;
    var decoded = try parent.codec.decode(a, bytes, &admission);
    var node = try parent.tree.Node.verifyOwned(&decoded, admission, expected_leaf_key_id, statement);
    defer node.deinit();
    try node.validate();
    return .{ .statement = statement, .admission = admission };
}

test "block-v5 leaf protocol is distinct from v3 custody protocol" {
    const config = @import("blake3_execution_parent_protocol.zig").PCS_CONFIG;
    try std.testing.expect(!std.meta.eql(protocolIdentity(config),
        @import("blake3_block_execution_span_v3.zig").protocolIdentity(config)));
}

test "block-v5 recursive leaf rejects invalid parent version before witness input" {
    const invalid = parent.protocol.Admission{
        .key = .{ .version = 0, .context = undefined, .log_sizes = undefined, .preprocessed_root = @splat(0) },
        .expected_id = @splat(0),
    };
    try std.testing.expectError(error.InvalidBlake3ParentProfile,
        verifyLeafBytes(std.testing.allocator, &.{}, invalid, @splat(0), undefined, undefined, undefined, undefined));
}
