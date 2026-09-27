//! Independently admitted B5CT/B5CF statement and exact optional-access layout.
//! `binding` is a proposed link to a capacity-native child, not evidence that
//! the native base proof was verified. The heterogeneous parent must prove it.
const std = @import("std");
const core = @import("stwo_core");
const NativeAdmission = @import("block_v5_native_capacity_recursive_admission_v1.zig");
const Native = @import("block_v5_native_capacity_proof_v1.zig");
const Capacity = @import("block_v5_native_capacity_protocol_v1.zig");
const Fused = @import("block_v5_native_capacity_fused_proof_v1.zig");
const Source = @import("block_v5_native_capacity_fused_source_v1.zig");
const Memory = @import("block_v5_opcode_memory_sidecar_proof_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Frame = @import("../air/block/memory_event.zig").Frame;
pub const VERSION: u32 = 1;
pub const Limits = struct {
    fused: Fused.Limits = .{},
    max_capture_bytes: usize = 256 << 20,
    max_preparation_bytes: usize = 512 << 20,
    max_public_wires: usize = 1 << 20,
};
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    /// Independent shape/catalog/public admission must outlive this object.
    native: *const NativeAdmission.Prepared,
    binding: Native.OpenReceipt,
    frame: Frame,
    witness_root: [32]u8,
    empty_entry: ?Seal.Entry,
    projections: []Source.Slot,
    slots: []Memory.Slot,
    /// Actual committed order. Empty access is omitted, not an empty tree.
    logs: [4][]u32,
    tree_count: usize,
    template_id: [32]u8,
    config: core.pcs.PcsConfig,
    limits: Limits,

    pub fn init(a: std.mem.Allocator, native: *const NativeAdmission.Prepared, binding: Native.OpenReceipt, frame: Frame, witness_root: [32]u8, limits: Limits) !Prepared {
        try native.validate(native.template_id);
        try limits.fused.requireShape(native.shape, native.external_retirements);
        const projections = try Source.slotsFromShapeForMode(a, native.shape, native.external_retirements, native.sealed.register_custody_mode);
        errdefer a.free(projections);
        const slots = try Source.memorySlots(a, native.shape, native.external_retirements, frame, native.sealed.register_custody_mode);
        errdefer a.free(slots);
        var empty: ?Seal.Entry = null;
        if (slots.len == 0) {
            const execution = try executionEntry(native.entries, native.index);
            empty = try Source.emptyEntry(a, native.shape, native.external_retirements, frame, execution, 0, native.sealed.register_custody_mode);
        }
        var self = Prepared{ .allocator = a, .native = native, .binding = binding, .frame = frame, .witness_root = witness_root, .empty_entry = empty, .projections = projections, .slots = slots, .logs = undefined, .tree_count = if (slots.len == 0) 3 else 4, .template_id = undefined, .config = native.config, .limits = limits };
        self.logs[0] = try a.dupe(u32, native.logs[0]);
        errdefer a.free(self.logs[0]);
        self.logs[1] = try a.dupe(u32, native.logs[1]);
        errdefer a.free(self.logs[1]);
        self.logs[2] = if (slots.len == 0) try Fused.interactionLogs(a, projections, slots) else try Fused.witnessLogs(a, slots);
        errdefer a.free(self.logs[2]);
        self.logs[3] = if (slots.len == 0) try a.alloc(u32, 0) else try Fused.interactionLogs(a, projections, slots);
        errdefer a.free(self.logs[3]);
        self.template_id = try self.templateId();
        try self.validate(self.template_id);
        return self;
    }
    pub fn deinit(self: *Prepared) void {
        for (self.logs) |logs| self.allocator.free(logs);
        self.allocator.free(self.projections);
        self.allocator.free(self.slots);
        self.* = undefined;
    }
    pub fn policy(self: *const Prepared) Fused.CaptureAdmission {
        return .{ .sealed = self.native.sealed, .pins = self.native.pins, .entries = self.native.entries, .native = &self.binding, .index = self.native.index, .frame = self.frame, .projections = self.projections, .slots = self.slots, .fixed_logs = self.logs[0], .main_logs = self.logs[1], .witness_root = self.witness_root, .empty_entry = self.empty_entry, .shape = self.native.shape, .external_retirements = self.native.external_retirements, .limits = self.limits.fused };
    }
    pub fn validate(self: *const Prepared, expected: [32]u8) !void {
        try self.native.validate(self.native.template_id);
        if (self.limits.max_capture_bytes == 0 or self.limits.max_preparation_bytes == 0 or self.limits.max_public_wires == 0 or !std.meta.eql(self.config, self.native.config) or !std.meta.eql(self.template_id, expected) or !std.meta.eql(try self.templateId(), expected)) return error.UntrustedCapacityFusedRecursiveAdmission;
        // This admits the native binding recipe, never its open claim.
        const id = try Capacity.instanceId(self.native.template_id, self.native.shape, self.native.external_retirements, self.native.pin, self.binding.first_roots, self.native.index);
        if (!std.meta.eql(self.binding.template_id, self.native.template_id) or !std.meta.eql(self.binding.instance_id, id) or !std.meta.eql(self.binding.sealed_digest, self.native.sealed.digest) or !std.meta.eql(self.binding.first_roots[0], self.native.template.fixed_root)) return error.UntrustedCapacityFusedNativeBinding;
        if (self.frame.clock_frame != .leaf_local or self.frame.global_first_cycle != self.native.pin.context.first_cycle or self.frame.cycle_count != self.native.shape.public_data.clock) return error.UntrustedCapacityFusedRecursiveSpan;
        try self.policy().require(self.allocator);
        if (self.tree_count != (if (self.slots.len == 0) @as(usize, 3) else 4) or !std.mem.eql(u32, self.logs[0], self.native.logs[0]) or !std.mem.eql(u32, self.logs[1], self.native.logs[1])) return error.UntrustedCapacityFusedRecursiveGeometry;
        const witness = try Fused.witnessLogs(self.allocator, self.slots);
        defer self.allocator.free(witness);
        const interaction = try Fused.interactionLogs(self.allocator, self.projections, self.slots);
        defer self.allocator.free(interaction);
        if (self.slots.len == 0) {
            if (self.logs[3].len != 0 or !std.mem.eql(u32, self.logs[2], interaction)) return error.UntrustedCapacityFusedRecursiveGeometry;
            const actual = try Source.emptyEntry(self.allocator, self.native.shape, self.native.external_retirements, self.frame, try executionEntry(self.native.entries, self.native.index), 0, self.native.sealed.register_custody_mode);
            if (self.empty_entry == null or !std.meta.eql(self.empty_entry.?, actual)) return error.UntrustedCapacityFusedRecursiveAbsence;
        } else if (self.empty_entry != null or !std.mem.eql(u32, self.logs[2], witness) or !std.mem.eql(u32, self.logs[3], interaction)) return error.UntrustedCapacityFusedRecursiveGeometry;
    }
    /// Counts, roots, instance/span and public claims are intentionally absent.
    /// Dynamic coordinates must be supplied by the authenticated public bus.
    pub fn templateId(self: *const Prepared) ![32]u8 {
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ 0x42355944, VERSION, Capacity.VERSION, Fused.VERSION, @intCast(self.tree_count), self.native.sealed.register_custody_mode, Fused.compositionSplit(self.projections), @intCast(self.projections.len), @intCast(self.slots.len) });
        self.config.mixInto(&channel);
        channel.mixRoot(sourceAuthorityDigest());
        for (self.logs[0..self.tree_count]) |logs| channel.mixU32s(logs);
        for (self.projections) |slot| {
            var geometry = slot;
            geometry.n_rows = 0;
            switch (geometry.kind) {
                .lookup => |*lookup| lookup.n_rows = 0,
                else => {},
            }
            Source.mixSlot(&channel, geometry);
            const binding = try Source.binding(self.native.shape, self.native.external_retirements, slot.main_offset, slot.log_size, slot.n_rows);
            channel.mixU32s(&.{ @intCast(binding.main_index), @intCast(binding.fixed_active_index), @intCast(binding.native_main_count) });
        }
        for (self.slots) |slot| channel.mixU32s(&.{ @intFromEnum(slot.family), @intCast(slot.slot), slot.log_size, @intCast(slot.main_offset), @intFromEnum(slot.frame.clock_frame) });
        return channel.digestBytes();
    }
};
fn executionEntry(entries: []const Seal.Entry, index: u32) !Seal.Entry {
    var found: ?Seal.Entry = null;
    for (entries) |entry| if (entry.family == .execution and entry.index == index) {
        if (found != null) return error.DuplicateCapacityFusedNativeEntry;
        found = entry;
    };
    return found orelse error.MissingCapacityFusedNativeEntry;
}

/// Exact typed equation/geometry/transcript source authority, without instance data.
pub fn sourceAuthorityDigest() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    inline for (.{ @embedFile("block_execution_integer_algebra_v1.zig"), @embedFile("block_v5_native_fused_algebra_v1.zig"), @embedFile("block_v5_native_capacity_fused_component_v1.zig"), @embedFile("../recursion/air/block_v5_native_capacity_fused_composition_v1.zig"), @embedFile("../recursion/air/block_v5_native_capacity_fused_statement_v1.zig"), @embedFile("../recursion/air/block_v5_native_capacity_fused_transcript_v1.zig"), @embedFile("../recursion/air/blake3_component_deep_v1.zig"), @embedFile("../recursion/air/block_v5_native_capacity_fused_roots_v1.zig") }) |bytes| hash.update(bytes);
    return hash.finalResult();
}
