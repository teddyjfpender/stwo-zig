//! Durable compact-node proof bytes. Host envelope/hash/pins are transport only;
//! fresh authority comes from the actual owned CPU parent receiver afterward.
const std = @import("std");
const Files = @import("block_v5_artifact_files_v1.zig");
const Owner = @import("../recursion/block_v5_heterogeneous_scoped_owner_v1.zig");
const Stage = @import("block_v5_heterogeneous_scoped_owned_stage_v1.zig");
const Receiver = @import("../recursion/block_v5_heterogeneous_scoped_owned_receiver_v1.zig");
pub const MAGIC = "B5ZOWN01";
pub const HEADER_BYTES: usize = 216;
pub const Pin = struct { index: u32, byte_len: u64, sha256: [32]u8 };
pub const Limits = struct { max_files: usize = 32768, max_slot_bytes: usize = 16 << 20, max_proof_bytes: usize = 512 << 20, max_total_bytes: u64 = 1 << 40 };
pub const Expected = struct { owner: [32]u8, routing: [32]u8, index: u32, key: [32]u8, public_input: [32]u8, source: [32]u8 };
pub fn header(expected: Expected, proof: []const u8, limits: Limits) ![HEADER_BYTES]u8 {
    if (proof.len == 0 or proof.len > limits.max_proof_bytes) return error.ScopedNodeFileResourceLimit;
    var result: [HEADER_BYTES]u8 = undefined;
    @memcpy(result[0..8], MAGIC);
    std.mem.writeInt(u32, result[8..12], 1, .little);
    std.mem.writeInt(u32, result[12..16], expected.index, .little);
    const hashes = [_][32]u8{ expected.owner, expected.routing, expected.key, expected.public_input, expected.source, Files.hash(proof) };
    for (hashes, 0..) |digest, i| @memcpy(result[16 + 32 * i ..][0..32], &digest);
    std.mem.writeInt(u64, result[208..216], proof.len, .little);
    return result;
}
pub fn admitHeader(raw: *const [HEADER_BYTES]u8, expected: Expected, total: u64, limits: Limits) !usize {
    if (!std.mem.eql(u8, raw[0..8], MAGIC) or std.mem.readInt(u32, raw[8..12], .little) != 1 or std.mem.readInt(u32, raw[12..16], .little) != expected.index) return error.UntrustedScopedNodeFile;
    const hashes = [_][32]u8{ expected.owner, expected.routing, expected.key, expected.public_input, expected.source };
    for (hashes, 0..) |digest, i| if (!std.mem.eql(u8, raw[16 + 32 * i ..][0..32], &digest)) return error.UntrustedScopedNodeFile;
    const count = std.mem.readInt(u64, raw[208..216], .little);
    if (count == 0 or count > limits.max_proof_bytes or count > std.math.maxInt(usize) or try std.math.add(u64, HEADER_BYTES, count) != total) return error.ScopedNodeFileResourceLimit;
    return @intCast(count);
}
const Slot = struct { pin: ?Pin = null, state: enum { pending, reading, failed } = .pending };
pub const Store = struct {
    a: std.mem.Allocator,
    dir: std.fs.Dir,
    owner: *const Owner.Owner,
    lease: Owner.Borrow,
    slots: []Slot,
    limits: Limits,
    total: u64 = 0,
    writer: bool,
    active: usize = 0,
    mutex: std.Thread.Mutex = .{},
    pub fn initWriter(a: std.mem.Allocator, dir: std.fs.Dir, owner: *const Owner.Owner, limits: Limits) !Store {
        if (!owner.ready or owner.nodes.len > limits.max_files or limits.max_proof_bytes == 0 or limits.max_total_bytes == 0 or try std.math.mul(usize, owner.nodes.len, @sizeOf(Slot)) > limits.max_slot_bytes) return error.ScopedNodeFileResourceLimit;
        for (0..owner.nodes.len) |i| _ = try owner.node(@intCast(i));
        var lease = try owner.borrow();
        errdefer lease.deinit();
        const slots = try a.alloc(Slot, owner.nodes.len);
        @memset(slots, .{});
        return .{ .a = a, .dir = dir, .owner = owner, .lease = lease, .slots = slots, .limits = limits, .writer = true };
    }
    pub fn initReader(a: std.mem.Allocator, dir: std.fs.Dir, owner: *const Owner.Owner, pins: []const Pin, limits: Limits) !Store {
        if (pins.len != owner.nodes.len or pins.len > limits.max_files) return error.IncompleteScopedNodeFiles;
        var total: u64 = 0;
        for (pins, 0..) |pin, index| {
            if (pin.index != index or pin.byte_len <= HEADER_BYTES or pin.byte_len - HEADER_BYTES > limits.max_proof_bytes or std.mem.allEqual(u8, &pin.sha256, 0)) return error.UntrustedScopedNodeFile;
            total = try std.math.add(u64, total, pin.byte_len);
            if (total > limits.max_total_bytes) return error.ScopedNodeFileResourceLimit;
        }
        var self = try initWriter(a, dir, owner, limits);
        for (self.slots, pins) |*slot, pin| slot.pin = pin;
        self.writer = false;
        self.total = total;
        return self;
    }
    pub fn deinit(self: *Store) void {
        self.mutex.lock();
        if (self.active != 0) @panic("destroying active compact node file reader");
        self.a.free(self.slots);
        self.lease.deinit();
        self.mutex.unlock();
        self.* = undefined;
    }
    fn expectedFor(self: *const Store, index: u32) !Expected {
        const admitted = try self.owner.node(index);
        return .{ .owner = self.owner.pinned_identity, .routing = self.owner.pins.routing, .index = index, .key = admitted.expected_id, .public_input = admitted.expected_public, .source = self.owner.nodes[index].spec.source_seal };
    }
    pub fn put(self: *Store, artifact: *Stage.Artifact) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.writer) return error.InvalidScopedNodeFileMode;
        if (artifact.ref == .leaf) {
            // True singleton: its original leaf remains in the original typed
            // leaf store. Never invent/publish a compact parent file for it.
            if (!std.meta.eql(artifact.ref, self.owner.cohorts.root) or artifact.key != null or self.slots.len != 0) return error.UntrustedScopedNodeFile;
            const source = try self.owner.source(artifact.ref);
            if (!std.meta.eql(artifact.key_id, source.expected_id) or !std.meta.eql(artifact.public_input, source.public_input_digest) or !std.meta.eql(artifact.coverage, self.owner.pins.routing) or artifact.wires.len != 0) return error.UntrustedScopedNodeFile;
            artifact.deinit(self.a);
            return;
        }
        const index = artifact.ref.node;
        const expected = try self.expectedFor(index);
        const admitted = try self.owner.node(index);
        if (artifact.key == null or !std.meta.eql(artifact.key.?, admitted.key) or !std.meta.eql(artifact.key_id, expected.key) or !std.meta.eql(artifact.public_input, expected.public_input) or !std.meta.eql(artifact.coverage, expected.routing) or !std.meta.eql(try @import("../recursion/block_v5_heterogeneous_scoped_public_bus_v1.zig").scheduleDigest(artifact.wires), admitted.key.public_schedule_digest)) return error.UntrustedScopedNodeFile;
        if (self.slots[index].pin != null) return error.DuplicateScopedNodeFile;
        const prefix = try header(expected, artifact.bytes, self.limits);
        const parts = [_][]const u8{ &prefix, artifact.bytes };
        const bytes = try std.math.add(u64, HEADER_BYTES, artifact.bytes.len);
        const total = try std.math.add(u64, self.total, bytes);
        if (total > self.limits.max_total_bytes) return error.ScopedNodeFileResourceLimit;
        var path: [96]u8 = undefined;
        try Files.publishParts(self.dir, try fileName(&path, index), &parts);
        self.slots[index].pin = .{ .index = index, .byte_len = bytes, .sha256 = Files.hashParts(&parts) };
        self.total = total;
        artifact.deinit(self.a);
    }
    pub fn proofBytes(self: *Store, a: std.mem.Allocator, index: u32) ![]u8 {
        const expected = try self.expectedFor(index);
        self.mutex.lock();
        if (index >= self.slots.len or self.slots[index].state != .pending or self.slots[index].pin == null) {
            self.mutex.unlock();
            return error.InvalidScopedNodeFileLoad;
        }
        const pin = self.slots[index].pin.?;
        self.slots[index].state = .reading;
        self.active += 1;
        self.mutex.unlock();
        var success = false;
        defer {
            self.mutex.lock();
            self.active -= 1;
            self.slots[index].state = if (success) .pending else .failed;
            self.mutex.unlock();
        }
        var path: [96]u8 = undefined;
        var file = try self.dir.openFile(try fileName(&path, index), .{});
        defer file.close();
        if ((try file.stat()).size != pin.byte_len) return error.UntrustedScopedNodeFile;
        var prefix: [HEADER_BYTES]u8 = undefined;
        if (try file.readAll(&prefix) != HEADER_BYTES) return error.UntrustedScopedNodeFile;
        const count = try admitHeader(&prefix, expected, pin.byte_len, self.limits);
        const proof = try a.alloc(u8, count);
        errdefer a.free(proof);
        if (try file.readAll(proof) != proof.len) return error.UntrustedScopedNodeFile;
        var tail: [1]u8 = undefined;
        if (try file.read(&tail) != 0 or !std.mem.eql(u8, prefix[176..208], &Files.hash(proof)) or !std.meta.eql(Files.hashParts(&.{ &prefix, proof }), pin.sha256)) return error.UntrustedScopedNodeFile;
        success = true;
        return proof; // Same allocation, no full envelope copy/no verification.
    }
    pub fn fresh(self: *Store, index: u32) !Receiver.Fresh {
        self.mutex.lock();
        self.active += 1;
        self.mutex.unlock();
        defer {
            self.mutex.lock();
            self.active -= 1;
            self.mutex.unlock();
        }
        const bytes = try self.proofBytes(self.a, index);
        defer self.a.free(bytes);
        return Receiver.verify(self.a, bytes, self.owner, index);
    }
    pub fn filePins(self: *Store, a: std.mem.Allocator) ![]Pin {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.active != 0) return error.ActiveScopedNodeFileReader;
        const result = try a.alloc(Pin, self.slots.len);
        errdefer a.free(result);
        for (result, self.slots) |*pin, slot| pin.* = slot.pin orelse return error.IncompleteScopedNodeFiles;
        return result;
    }
    pub fn sink(self: *Store) Stage.Sink {
        return .{ .context = self, .put_scoped_open = putThunk };
    }
    fn putThunk(context: *anyopaque, artifact: *Stage.Artifact) !void {
        return @as(*Store, @ptrCast(@alignCast(context))).put(artifact);
    }
};
fn fileName(buffer: []u8, index: u32) ![]const u8 {
    return std.fmt.bufPrint(buffer, "compact-node-{d:0>8}.b5z", .{index});
}
