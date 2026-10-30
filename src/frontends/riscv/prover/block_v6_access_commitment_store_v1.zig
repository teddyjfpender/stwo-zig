//! Retain ordinary-access auxiliary witness and its original PCS tree.
//! Cache cells and counter snapshots are untrusted proving inputs; interaction
//! generation and fresh AIR/PCS/global closure verification remain mandatory.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const codec = @import("block_v6_cpu_checkpoint_codec_v1.zig");
const Native = @import("block_v5_cpu_native_root_proposal_v1.zig");
const Memory = @import("block_v5_native_memory_stage_v1.zig");
const Slots = @import("block_execution_sidecar_batch_v2.zig");
const Integer = @import("block_execution_integer_bridge_v2.zig");
const Bytes = @import("block_execution_byte_range_v2.zig");
const Owner = @import("blake3_execution_trace.zig").Owner;
const Public = @import("block_v5_native_public_admission_v1.zig");
const Trace = @import("block_execution_sidecar_trace_v2.zig").Trace;
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const Hash = [32]u8;
const HEADER_BYTES: u64 = 80;
pub const Limits = struct {
    source: Memory.Limits,
    storage: @import("block_v6_native_commitment_store_v1.zig").Limits = .{},
};
pub const Pin = struct {
    bytes: u64,
    raw_witness_bytes: u64,
    snapshot_bytes: u64,
    column_bytes: u64,
    merkle_bytes: u64,
    /// Persistent restored storage/descriptors; excludes temporary geometry,
    /// the borrowed native owner/trees and subsequent proof scratch.
    loaded_bytes: usize,
};
pub const Loaded = struct {
    source: Memory.Traces,
    scheme: codec.Scheme,
    snapshots: []Bytes.SNAPSHOT,
    pub fn deinit(self: *Loaded, a: std.mem.Allocator) void {
        self.source.deinit();
        self.scheme.deinit(a);
        a.free(self.snapshots);
        self.* = undefined;
    }
};
const Shape = struct {
    a: std.mem.Allocator,
    logs: []u32,
    layer_count: usize,
    header: [HEADER_BYTES]u8,
    raw_bytes: u64,
    snapshot_bytes: u64,
    column_bytes: u64,
    descriptors: u64,
    max_merkle_bytes: u64,
    fn init(a: std.mem.Allocator, native: *const Native.Proposal, access: *const Memory.Proposal, limits: Limits) !Shape {
        try native.template.admit(&native.shape, native.template_id);
        if (!std.meta.eql(Public.publicDigest(&native.shape.public_data), native.public_digest) or
            access.slots.len == 0 or access.slots.len > limits.source.max_slots or
            access.register_custody_mode != limits.source.register_custody_mode or
            access.index != native.index or !std.meta.eql(access.native_roots, native.roots) or
            !std.meta.eql(access.template_id, native.template_id) or access.frame.global_first_cycle != native.first_cycle or
            access.frame.cycle_count != native.shape.total_steps or access.frame.cycle_count == 0 or
            native.last_cycle != try std.math.add(u64, native.first_cycle, access.frame.cycle_count - 1)) return error.ChangedAccessCheckpointScope;
        const slots = try Slots.slotsFromStatementForMode(a, &native.shape, access.frame, access.register_custody_mode);
        defer a.free(slots);
        if (!sameSlots(slots, access.slots)) return error.ChangedAccessCheckpointScope;
        const metadata = try std.math.add(usize, @sizeOf(Memory.Proposal), try std.math.mul(usize, slots.len, @sizeOf(Slots.Slot)));
        const n = try std.math.mul(usize, slots.len, Integer.COLUMN_COUNT);
        if (metadata > limits.source.max_metadata_bytes or n > limits.storage.max_columns or n > std.math.maxInt(u32)) return error.AccessCheckpointResourceLimit;
        const logs = try a.alloc(u32, n);
        errdefer a.free(logs);
        var raw: u64 = 0;
        var extended: u64 = 0;
        var maximum: u32 = 0;
        for (slots, 0..) |slot, i| {
            const log = try std.math.add(u32, slot.log_size, native.template.config.fri_config.log_blowup_factor);
            if (slot.log_size == 0 or slot.log_size > 24 or log > limits.storage.max_log_size or log > 30) return error.AccessCheckpointResourceLimit;
            maximum = @max(maximum, log);
            @memset(logs[i * Integer.COLUMN_COUNT ..][0..Integer.COLUMN_COUNT], log);
            raw = try std.math.add(u64, raw, try std.math.mul(u64, Integer.COLUMN_COUNT, @as(u64, 4) << @intCast(slot.log_size)));
            extended = try std.math.add(u64, extended, try std.math.mul(u64, Integer.COLUMN_COUNT, @as(u64, 4) << @intCast(log)));
        }
        if (raw / 4 > limits.source.max_witness_cells) return error.AccessCheckpointResourceLimit;
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ 0x42364143, 1, access.register_custody_mode });
        Slots.mixRoster(&channel, access.index, native.template_id, slots);
        channel.mixRoot(native.public_digest);
        channel.mixRoot(native.roots[0]);
        channel.mixRoot(native.roots[1]);
        channel.mixRoot(access.witness_root);
        channel.mixRoot(access.byte_snapshot);
        channel.mixU64(access.ordinary_events);
        var header: [HEADER_BYTES]u8 = @splat(0);
        @memcpy(header[0..8], "B6ACC001");
        std.mem.writeInt(u32, header[8..12], 1, .little);
        @memcpy(header[16..48], &channel.digestBytes());
        @memcpy(header[48..80], &access.witness_root);
        const layers = maximum + 1;
        const descriptors = try std.math.add(u64, @sizeOf(codec.Tree) + n * @sizeOf(Column) + layers * @sizeOf([]Hash), try std.math.mul(u64, slots.len, @sizeOf(Slots.Slot) + @sizeOf(Trace) + @sizeOf(Slots.Input)));
        const result = Shape{ .a = a, .logs = logs, .layer_count = layers, .header = header, .raw_bytes = raw, .snapshot_bytes = slots.len * @sizeOf(Bytes.SNAPSHOT), .column_bytes = extended, .descriptors = descriptors, .max_merkle_bytes = ((@as(u64, 1) << @intCast(maximum + 1)) - 1) * @sizeOf(Hash) };
        _ = try result.pin(@sizeOf(Hash), limits);
        return result;
    }
    fn deinit(self: *Shape) void {
        self.a.free(self.logs);
    }
    fn pin(self: Shape, merkle: u64, limits: Limits) !Pin {
        if (merkle < @sizeOf(Hash) or merkle > self.max_merkle_bytes) return error.InvalidAccessCheckpointLayers;
        const payload = try std.math.add(u64, try std.math.add(u64, self.raw_bytes, self.snapshot_bytes), try std.math.add(u64, self.column_bytes, merkle));
        const bytes = try std.math.add(u64, payload, HEADER_BYTES + 8 + self.logs.len * 4 + self.layer_count * 8);
        const loaded = try std.math.add(u64, payload, self.descriptors);
        if (bytes > limits.storage.max_file_bytes or loaded > limits.storage.max_loaded_bytes) return error.AccessCheckpointResourceLimit;
        return .{ .bytes = bytes, .raw_witness_bytes = self.raw_bytes, .snapshot_bytes = self.snapshot_bytes, .column_bytes = self.column_bytes, .merkle_bytes = merkle, .loaded_bytes = @intCast(loaded) };
    }
};

pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, native: *const Native.Proposal, retained: *const Memory.ForBackend(Cpu).Retained, limits: Limits) !Pin {
    try codec.requireName(name);
    const access = &retained.proposal;
    var shape = try Shape.init(a, native, access, limits);
    defer shape.deinit();
    if (retained.scheme.trees.items.len != 1 or retained.scheme.pending_commit != null or
        !std.meta.eql(retained.scheme.config, native.template.config) or retained.snapshots.len != access.slots.len or
        !sameSlots(retained.source.slots, access.slots) or retained.source.traces.len != access.slots.len) return error.ChangedAccessCheckpointScope;
    for (retained.source.traces, access.slots) |trace, slot| {
        if (trace.family != slot.family or trace.slot != slot.slot or trace.log_size != slot.log_size or
            trace.register_custody_mode != access.register_custody_mode or !std.meta.eql(trace.frame, slot.frame) or
            trace.storage.len != Integer.COLUMN_COUNT * (@as(usize, 1) << @intCast(slot.log_size))) return error.ChangedAccessCheckpointScope;
        for (trace.witness, 0..) |column, i| if (column.len != trace.domainSize() or column.ptr != trace.storage[i * trace.domainSize() ..].ptr) return error.ChangedAccessCheckpointScope;
    }
    const merkle = try codec.inspectTree(&retained.scheme.trees.items[0], shape.logs, shape.layer_count, access.witness_root);
    const pin = try shape.pin(merkle, limits);
    const temporary = try std.fmt.allocPrint(a, ".{s}.partial", .{name});
    defer a.free(temporary);
    const file = try dir.createFile(temporary, .{ .exclusive = true });
    defer file.close();
    var published = false;
    defer if (!published) dir.deleteFile(temporary) catch {};
    try file.writeAll(&shape.header);
    for (retained.source.traces) |trace| try codec.writeValues(file, trace.storage);
    try file.writeAll(std.mem.sliceAsBytes(retained.snapshots));
    try codec.writeTree(file, &retained.scheme.trees.items[0]);
    if ((try file.stat()).size != pin.bytes) return error.InvalidAccessCheckpointLength;
    try file.sync();
    if (dir.openFile(name, .{})) |existing| {
        existing.close();
        return error.AccessCheckpointAlreadyExists;
    } else |err| if (err != error.FileNotFound) return err;
    try dir.rename(temporary, name);
    published = true;
    return pin;
}

pub fn load(a: std.mem.Allocator, dir: std.fs.Dir, name: []const u8, native: *const Native.Proposal, access: *const Memory.Proposal, owner: *Owner, pin: Pin, limits: Limits) !Loaded {
    try codec.requireName(name);
    var shape = try Shape.init(a, native, access, limits);
    defer shape.deinit();
    if (!std.meta.eql(pin, try shape.pin(pin.merkle_bytes, limits))) return error.InvalidAccessCheckpointLength;
    try native.template.admit(&owner.statement, native.template_id);
    if (!owner.native_only_v5 or owner.failed or !owner.tables_ready or owner.interaction_ready or
        !std.meta.eql(Public.publicDigest(&owner.statement.public_data), native.public_digest)) return error.ChangedAccessCheckpointScope;
    const file = try dir.openFile(name, .{});
    defer file.close();
    if ((try file.stat()).size != pin.bytes) return error.InvalidAccessCheckpointLength;
    var header: [HEADER_BYTES]u8 = undefined;
    try codec.readExact(file, &header);
    if (!std.mem.eql(u8, &header, &shape.header)) return error.ChangedAccessCheckpointScope;
    var source = try Memory.Traces.allocateForCheckpoint(a, owner, access.frame, limits.source);
    errdefer source.deinit();
    if (!sameSlots(source.slots, access.slots)) return error.ChangedAccessCheckpointScope;
    for (source.traces) |*trace| try codec.readValues(file, trace.storage);
    const snapshots = try a.alloc(Bytes.SNAPSHOT, access.slots.len);
    errdefer a.free(snapshots);
    try codec.readExact(file, std.mem.sliceAsBytes(snapshots));
    var scheme = try codec.Scheme.init(a, native.template.config);
    errdefer scheme.deinit(a);
    scheme.setCoefficientRetentionPolicy(.never);
    try scheme.trees.ensureTotalCapacityPrecise(a, 1);
    var used: u64 = 0;
    var tree = try codec.loadTree(a, file, shape.logs, shape.layer_count, &used, pin.merkle_bytes);
    errdefer tree.deinit(a);
    if (used != pin.merkle_bytes) return error.InvalidAccessCheckpointLength;
    if (!std.meta.eql(tree.commitment.root(), access.witness_root)) return error.ChangedAccessCheckpointRoot;
    var extra: [1]u8 = undefined;
    if (try file.read(&extra) != 0) return error.InvalidAccessCheckpointLength;
    scheme.trees.appendAssumeCapacity(tree);
    return .{ .source = source, .scheme = scheme, .snapshots = snapshots };
}

fn sameSlots(left: []const Slots.Slot, right: []const Slots.Slot) bool {
    if (left.len != right.len) return false;
    for (left, right) |lhs, rhs| if (!std.meta.eql(lhs, rhs)) return false;
    return true;
}
