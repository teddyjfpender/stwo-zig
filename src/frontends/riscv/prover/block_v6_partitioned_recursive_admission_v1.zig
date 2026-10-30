//! Independent native statement, exact relation basis and recursive key policy.
const std = @import("std");
const core = @import("stwo_core");
const Native = @import("block_v5_native_recursive_admission_v3.zig");
const Fused = @import("block_v5_native_projection_fused_proof_v2.zig");
const Protocol = @import("block_v6_partitioned_native_proof_v1.zig");
const Receiver = @import("block_v5_native_projection_fused_receiver_v2.zig");
const Layout = @import("block_v6_relation_layout_v1.zig").Layout;
const Memory = @import("block_v5_opcode_memory_sidecar_proof_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Source = @import("block_v5_native_projection_fused_source_v1.zig");
pub const Limits = struct { max_capture_bytes: usize = 256 << 20, max_preparation_bytes: usize = 512 << 20, max_public_wires: usize = 1 << 20, max_metadata_bytes: usize = 16 << 20 };
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    native: *const Native.Prepared,
    memory: Receiver.MemoryPin,
    frame: @import("../air/block/memory_event.zig").Frame,
    witness_root: [32]u8,
    binding: Protocol.Identity,
    projections: []Source.Slot,
    slots: []Memory.Slot,
    layout_digest: [32]u8,
    logs: [4][]u32,
    tree_count: usize,
    config: core.pcs.PcsConfig,
    template_id: [32]u8,
    limits: Limits,
    pub fn init(a: std.mem.Allocator, native: *const Native.Prepared, memory: Receiver.MemoryPin, limits: Limits) !Prepared {
        try native.validate(native.expected_id);
        var layout = try Layout.init(a, native.shape, native.template.external_retirements, native.sealed.register_custody_mode);
        errdefer layout.deinit();
        const binding = try Protocol.admitIdentity(a, native.index, instancePin(native), memory, native.sealed, native.pins, native.entries, native.catalog orelse return error.MissingPartitionedCatalog, &layout);
        const slots = try @import("block_execution_sidecar_batch_v2.zig").slotsFromStatementForMode(a, native.shape, memory.frame, native.sealed.register_custody_mode);
        errdefer a.free(slots);
        var self = Prepared{ .allocator = a, .native = native, .memory = memory, .frame = memory.frame, .witness_root = memory.witness_root, .binding = binding, .projections = layout.slots, .slots = slots, .layout_digest = layout.digest, .logs = undefined, .tree_count = if (slots.len == 0) 3 else 4, .config = native.config, .template_id = undefined, .limits = limits };
        self.logs[0] = try a.dupe(u32, native.logs[0]);
        errdefer a.free(self.logs[0]);
        self.logs[1] = try a.dupe(u32, native.logs[1]);
        errdefer a.free(self.logs[1]);
        self.logs[2] = if (slots.len == 0) try Protocol.interactionLogs(a, layout.slots, slots) else try Fused.witnessLogs(a, slots);
        errdefer a.free(self.logs[2]);
        self.logs[3] = if (slots.len == 0) try a.alloc(u32, 0) else try Protocol.interactionLogs(a, layout.slots, slots);
        errdefer a.free(self.logs[3]);
        self.template_id = self.templateId();
        try self.validate(self.template_id);
        return self;
    }
    pub fn deinit(self: *Prepared) void {
        for (self.logs) |logs| self.allocator.free(logs);
        self.allocator.free(self.projections);
        self.allocator.free(self.slots);
        self.* = undefined;
    }
    pub fn validate(self: *const Prepared, expected: [32]u8) !void {
        try self.native.validate(self.native.expected_id);
        if (self.limits.max_capture_bytes == 0 or self.limits.max_preparation_bytes == 0 or self.limits.max_public_wires == 0 or self.limits.max_metadata_bytes == 0 or !std.meta.eql(expected, self.template_id) or !std.meta.eql(expected, self.templateId()) or !std.meta.eql(self.config, self.native.config) or !std.meta.eql(self.frame, self.memory.frame) or !std.meta.eql(self.witness_root, self.memory.witness_root)) return error.UntrustedPartitionedRecursiveAdmission;
        var layout = try Layout.init(self.allocator, self.native.shape, self.native.template.external_retirements, self.native.sealed.register_custody_mode);
        defer layout.deinit();
        if (!std.meta.eql(layout.digest, self.layout_digest) or layout.slots.len != self.projections.len) return error.UntrustedPartitionedRecursiveLayout;
        for (layout.slots, self.projections) |want, got| if (!std.meta.eql(want, got)) return error.UntrustedPartitionedRecursiveLayout;
        const identity = try Protocol.admitIdentity(self.allocator, self.native.index, instancePin(self.native), self.memory, self.native.sealed, self.native.pins, self.native.entries, self.native.catalog orelse return error.MissingPartitionedCatalog, &layout);
        if (!std.meta.eql(identity, self.binding)) return error.UntrustedPartitionedRecursiveIdentity;
        const slots = try @import("block_execution_sidecar_batch_v2.zig").slotsFromStatementForMode(self.allocator, self.native.shape, self.frame, self.native.sealed.register_custody_mode);
        defer self.allocator.free(slots);
        if (slots.len != self.slots.len) return error.UntrustedPartitionedRecursiveGeometry;
        for (slots, self.slots) |want, got| if (!std.meta.eql(want, got)) return error.UntrustedPartitionedRecursiveGeometry;
        const witness = try Fused.witnessLogs(self.allocator, slots);
        defer self.allocator.free(witness);
        const interactions = try Protocol.interactionLogs(self.allocator, self.projections, slots);
        defer self.allocator.free(interactions);
        if (self.tree_count != (if (slots.len == 0) @as(usize, 3) else 4) or !std.mem.eql(u32, self.logs[0], self.native.logs[0]) or !std.mem.eql(u32, self.logs[1], self.native.logs[1]) or !std.mem.eql(u32, self.logs[self.tree_count - 1], interactions) or (slots.len == 0 and self.logs[3].len != 0) or (slots.len != 0 and !std.mem.eql(u32, self.logs[2], witness))) return error.UntrustedPartitionedRecursiveGeometry;
    }
    pub fn templateId(self: *const Prepared) [32]u8 {
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ 0x4236524b, Protocol.VERSION, @intCast(self.tree_count), self.native.shape.x0_local_custody_version });
        self.config.mixInto(&channel);
        channel.mixRoot(sourceAuthorityDigest());
        // Physical shape fixes the equation graph; row counts, machine
        // endpoints, source seal and actual roots travel on the public bus.
        // Normalizing only row counts preserves template reuse across distinct
        // admitted segments with the same physical layout.
        channel.mixU32s(&.{ self.native.shape.n_components, self.native.shape.n_infra });
        for (self.native.shape.component_descs[0..self.native.shape.n_components]) |desc| channel.mixU32s(&.{ @intFromEnum(desc.family), desc.log_size, desc.n_columns });
        for (self.native.shape.infra_descs[0..self.native.shape.n_infra]) |desc| channel.mixU32s(&.{ @intFromEnum(desc.kind), desc.log_size, desc.n_columns });
        if (@import("block_v5_native_frame_v1.zig").required(self.native.shape)) channel.mixU32s(&.{ self.native.shape.total_steps, self.native.template.external_retirements });
        for (self.projections) |slot| {
            var geometry = slot;
            geometry.n_rows = 0;
            if (geometry.kind == .lookup) geometry.kind.lookup.n_rows = 0;
            Source.mixSlot(&channel, geometry);
        }
        for (self.slots) |slot| channel.mixU32s(&.{ @intFromEnum(slot.family), @intCast(slot.slot), slot.log_size, @intCast(slot.main_offset), @intFromEnum(slot.frame.clock_frame) });
        for (self.logs[0..self.tree_count]) |logs| channel.mixU32s(logs);
        return channel.digestBytes();
    }
};
pub fn instancePin(native: *const Native.Prepared) Receiver.InstancePin {
    return .{ .shape = native.shape, .admission = native.pin, .template = native.template, .template_id = native.expected_id, .profile = native.template.execution_profile };
}
pub fn sourceAuthorityDigest() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    inline for (.{ "block_v6_relation_layout_v1.zig", "block_v6_partitioned_native_proof_v1.zig", "block_v6_partitioned_native_components_v1.zig", "block_v6_direct_component_v1.zig", "block_v6_joint_components_v1.zig", "block_v5_native_fused_algebra_v1.zig", "block_v5_native_projection_fused_proof_v2.zig", "../air/semantic_eval.zig", "../air/clock_update_component.zig", "../air/x0_native_envelope_v1.zig", "block_execution_integer_algebra_v1.zig", "../recursion/air/block_v6_partitioned_composition_v1.zig", "../recursion/air/block_v6_partitioned_statement_v1.zig", "../recursion/air/block_v6_partitioned_transcript_v1.zig", "../recursion/air/block_v6_partitioned_roots_v1.zig", "../recursion/air/blake3_component_deep_v1.zig" }) |path| hash.update(@embedFile(path));
    return hash.finalResult();
}
