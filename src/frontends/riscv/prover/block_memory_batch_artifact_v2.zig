//! Staged, bounded files for the memory+range portion of a block-v2 batch.
//! A completion marker is published atomically only after all files pass a
//! fresh batch verification. It never denotes a complete Ethereum block.
const std = @import("std");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
const postcard = @import("interop_postcard");
const batch = @import("block_memory_batch_verify_v2.zig");
const memory_proof = @import("block_memory_shared_instance_proof_v2.zig");
const table_proof = @import("block_memory_shared_table_proof_v2.zig");
const shard_mod = @import("block_memory_range_shard_v2.zig");
const bus = @import("block_memory_relation_v2.zig");
const range = @import("../air/block/memory_range_interaction_v2.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Digest = [32]u8;
const marker_name = "memory-range.complete.v2";
const marker_tmp = "memory-range.complete.v2.tmp";
const magic_memory = "B2MI";
const magic_table = "B2TB";
const magic_marker = "B2MRDONE";
const version: u32 = 2;
const max_file_bytes: usize = batch.MAX_STARK_BYTES + 4096;

fn filename(a: std.mem.Allocator, comptime prefix: []const u8, index: u32) ![]u8 {
    return std.fmt.allocPrint(a, prefix ++ "-{d}.v2", .{index});
}
fn writeU32(writer: anytype, value: u32) !void {
    var word: [4]u8 = undefined;
    std.mem.writeInt(u32, &word, value, .little);
    try writer.writeAll(&word);
}
fn writeQ(writer: anytype, value: Q) !void {
    for (value.toM31Array()) |limb| try writeU32(writer, limb.toU32());
}
fn readWord(bytes: []const u8) u32 {
    var word: [4]u8 = undefined;
    @memcpy(&word, bytes[0..4]);
    return std.mem.readInt(u32, &word, .little);
}
const Cursor = struct {
    bytes: []const u8,
    at: usize = 0,
    fn take(self: *Cursor, count: usize) ![]const u8 {
        if (count > self.bytes.len - self.at) return error.TruncatedBlockProofArtifact;
        defer self.at += count;
        return self.bytes[self.at..][0..count];
    }
    fn readU32(self: *Cursor) !u32 {
        return readWord(try self.take(4));
    }
    fn q(self: *Cursor) !Q {
        var limbs: [4]M = undefined;
        for (&limbs) |*limb| {
            const value = try self.readU32();
            if (value >= core.fields.m31.Modulus) return error.NonCanonicalBlockProofClaim;
            limb.* = M.fromCanonical(value);
        }
        return Q.fromM31Array(limbs);
    }
};
fn digest(bytes: []const u8) Digest {
    var result: Digest = undefined;
    std.crypto.hash.Blake3.hash(bytes, &result, .{});
    return result;
}

pub const StagedWriter = struct {
    a: std.mem.Allocator,
    dir: std.fs.Dir,
    memory_digests: []Digest,
    table_digests: []Digest,
    next_memory: u32 = 0,
    next_table: u32 = 0,

    pub fn init(a: std.mem.Allocator, dir: std.fs.Dir, memory_count: usize, table_count: usize) !StagedWriter {
        if (memory_count == 0 or table_count == 0 or memory_count > std.math.maxInt(u32) or table_count > std.math.maxInt(u32))
            return error.InvalidBlockProofCensus;
        if (dir.openFile(marker_name, .{})) |file| {
            file.close();
            return error.AlreadyPublishedBlockMemoryRange;
        } else |err| if (err != error.FileNotFound) return err;
        const memory_digests = try a.alloc(Digest, memory_count);
        errdefer a.free(memory_digests);
        const table_digests = try a.alloc(Digest, table_count);
        return .{ .a = a, .dir = dir, .memory_digests = memory_digests, .table_digests = table_digests };
    }
    pub fn deinit(self: *StagedWriter) void {
        self.a.free(self.memory_digests);
        self.a.free(self.table_digests);
        self.* = undefined;
    }
    pub fn proofSink(self: *StagedWriter) @import("block_memory_batch_produce_v2.zig").ProofSink {
        return .{ .context = self, .write_memory = onMemory, .write_table = onTable };
    }
    fn onMemory(context: *anyopaque, index: u32, _: @import("../air/block/memory_component.zig").Claim, proof: *const memory_proof.Proof) anyerror!void {
        const self: *StagedWriter = @ptrCast(@alignCast(context));
        if (index != self.next_memory or index >= self.memory_digests.len or self.next_table != 0)
            return error.InvalidStagedMemoryProofOrder;
        var out = std.Io.Writer.Allocating.init(self.a);
        defer out.deinit();
        try out.writer.writeAll(magic_memory);
        try writeU32(&out.writer, version);
        try writeU32(&out.writer, index);
        try writeU32(&out.writer, proof.relation.instance_index);
        try writeQ(&out.writer, proof.relation.transition_sum);
        try writeQ(&out.writer, proof.relation.link_sum);
        try writeQ(&out.writer, proof.relation.initial_sum);
        for (proof.range_claims) |claim| try writeQ(&out.writer, claim);
        try postcard.serializeProof(suite.Hasher, &out.writer, proof.stark);
        try self.writeFile("memory", index, out.written(), &self.memory_digests[index]);
        self.next_memory += 1;
    }
    fn onTable(context: *anyopaque, shard: shard_mod.Shard, proof: *const table_proof.Proof) anyerror!void {
        const self: *StagedWriter = @ptrCast(@alignCast(context));
        if (self.next_memory != self.memory_digests.len or shard.index != self.next_table or shard.index >= self.table_digests.len)
            return error.InvalidStagedTableProofOrder;
        var out = std.Io.Writer.Allocating.init(self.a);
        defer out.deinit();
        try out.writer.writeAll(magic_table);
        try writeU32(&out.writer, version);
        try writeU32(&out.writer, shard.index);
        try writeQ(&out.writer, proof.claim);
        try postcard.serializeProof(suite.Hasher, &out.writer, proof.stark);
        try self.writeFile("table", shard.index, out.written(), &self.table_digests[shard.index]);
        self.next_table += 1;
    }
    fn writeFile(self: *StagedWriter, comptime prefix: []const u8, index: u32, bytes: []const u8, out_digest: *Digest) !void {
        if (bytes.len > max_file_bytes) return error.BlockProofArtifactTooLarge;
        const name = try filename(self.a, prefix, index);
        defer self.a.free(name);
        var file = try self.dir.createFile(name, .{ .exclusive = true });
        defer file.close();
        try file.writeAll(bytes);
        try file.sync();
        out_digest.* = digest(bytes);
    }

    /// Verifies the staged files through the same fresh PCS receiver used by
    /// external consumers, then atomically publishes only a scoped marker.
    pub fn verifyAndPublish(self: *StagedWriter, comptime Backend: type, statement: batch.PinnedStatement, config: core.pcs.PcsConfig) !void {
        if (self.next_memory != self.memory_digests.len or self.next_table != self.table_digests.len or
            self.next_memory != statement.memory_instances.len or self.next_table != statement.range_table_roots.len)
            return error.IncompleteStagedBlockMemoryRange;
        var loaded = try loadUnchecked(self.a, self.dir, statement, self.memory_digests, self.table_digests);
        defer loaded.deinit();
        try batch.verifyMemoryRangeOnly(Backend, self.a, statement, loaded.wire(), config);
        const marker = markerBytes(statement, self.memory_digests, self.table_digests);
        var file = try self.dir.createFile(marker_tmp, .{ .exclusive = true });
        errdefer self.dir.deleteFile(marker_tmp) catch {};
        defer file.close();
        try file.writeAll(&marker);
        try file.sync();
        try self.dir.rename(marker_tmp, marker_name);
    }
};

pub const OwnedBatch = struct {
    a: std.mem.Allocator,
    memory: []batch.SerializedMemoryProof,
    tables: []batch.SerializedTableProof,
    memory_files: [][]u8,
    table_files: [][]u8,
    pub fn deinit(self: *OwnedBatch) void {
        for (self.memory_files) |bytes| self.a.free(bytes);
        for (self.table_files) |bytes| self.a.free(bytes);
        self.a.free(self.memory_files);
        self.a.free(self.table_files);
        self.a.free(self.memory);
        self.a.free(self.tables);
        self.* = undefined;
    }
    pub fn wire(self: *const OwnedBatch) batch.SerializedBatch {
        return .{ .memory = self.memory, .range_tables = self.tables, .execution = &.{}, .initial_sources = &.{} };
    }
};

fn loadUnchecked(a: std.mem.Allocator, dir: std.fs.Dir, statement: batch.PinnedStatement, memory_digests: []const Digest, table_digests: []const Digest) !OwnedBatch {
    if (memory_digests.len != statement.memory_instances.len or table_digests.len != statement.range_table_roots.len)
        return error.InvalidBlockProofCensus;
    const memory_wire = try a.alloc(batch.SerializedMemoryProof, memory_digests.len);
    errdefer a.free(memory_wire);
    const table_wire = try a.alloc(batch.SerializedTableProof, table_digests.len);
    errdefer a.free(table_wire);
    const memory_files = try a.alloc([]u8, memory_digests.len);
    errdefer a.free(memory_files);
    const table_files = try a.alloc([]u8, table_digests.len);
    errdefer a.free(table_files);
    var result = OwnedBatch{ .a = a, .memory = memory_wire, .tables = table_wire, .memory_files = memory_files, .table_files = table_files };
    var memory_loaded: usize = 0;
    var table_loaded: usize = 0;
    errdefer {
        for (result.memory_files[0..memory_loaded]) |bytes| a.free(bytes);
        for (result.table_files[0..table_loaded]) |bytes| a.free(bytes);
    }
    for (memory_digests, 0..) |expected, i| {
        const name = try filename(a, "memory", @intCast(i));
        defer a.free(name);
        const bytes = try dir.readFileAlloc(a, name, max_file_bytes);
        result.memory_files[i] = bytes;
        memory_loaded += 1;
        if (!std.meta.eql(digest(bytes), expected)) return error.StagedBlockProofDigestMismatch;
        var cursor = Cursor{ .bytes = bytes };
        if (!std.mem.eql(u8, try cursor.take(4), magic_memory) or try cursor.readU32() != version or try cursor.readU32() != i)
            return error.InvalidStagedBlockProofHeader;
        const instance_index = try cursor.readU32();
        const relation = bus.ComponentClaim{ .instance_index = instance_index, .transition_sum = try cursor.q(), .link_sum = try cursor.q(), .initial_sum = try cursor.q() };
        var claims: range.Claims = undefined;
        for (&claims) |*claim| claim.* = try cursor.q();
        result.memory[i] = .{ .stark_bytes = bytes[cursor.at..], .interaction_claim = relation, .range_claims = claims };
    }
    for (table_digests, 0..) |expected, i| {
        const name = try filename(a, "table", @intCast(i));
        defer a.free(name);
        const bytes = try dir.readFileAlloc(a, name, max_file_bytes);
        result.table_files[i] = bytes;
        table_loaded += 1;
        if (!std.meta.eql(digest(bytes), expected)) return error.StagedBlockProofDigestMismatch;
        var cursor = Cursor{ .bytes = bytes };
        if (!std.mem.eql(u8, try cursor.take(4), magic_table) or try cursor.readU32() != version or try cursor.readU32() != i)
            return error.InvalidStagedBlockProofHeader;
        const claim = try cursor.q();
        result.tables[i] = .{ .stark_bytes = bytes[cursor.at..], .claim = claim };
    }
    return result;
}

fn markerBytes(statement: batch.PinnedStatement, memory_digests: []const Digest, table_digests: []const Digest) [148]u8 {
    var bytes: [148]u8 = undefined;
    @memcpy(bytes[0..8], magic_marker);
    std.mem.writeInt(u32, bytes[8..12], version, .little);
    std.mem.writeInt(u32, bytes[12..16], @intCast(memory_digests.len), .little);
    std.mem.writeInt(u32, bytes[16..20], @intCast(table_digests.len), .little);
    var channel = statement.seal.sharedChannel();
    const seal_digest = channel.digestBytes();
    @memcpy(bytes[20..52], &seal_digest);
    @memcpy(bytes[52..84], &statement.seal.first_round_roster_digest);
    @memcpy(bytes[84..116], &statement.seal.range_shard_digest);
    var hash = std.crypto.hash.Blake3.init(.{});
    hash.update("stwo-zig/block-memory/staged-files/v2\x00");
    for (memory_digests) |item| hash.update(&item);
    for (table_digests) |item| hash.update(&item);
    var aggregate: Digest = undefined;
    hash.final(&aggregate);
    @memcpy(bytes[116..148], &aggregate);
    return bytes;
}

/// Public reader requires the atomically published scoped marker and then
/// independently recomputes all file digests and verifies every PCS proof.
pub fn verifyPublished(comptime Backend: type, a: std.mem.Allocator, dir: std.fs.Dir, statement: batch.PinnedStatement, config: core.pcs.PcsConfig) !void {
    var plan = try statement.validate(a);
    defer plan.deinit(a);
    const marker = try dir.readFileAlloc(a, marker_name, 148);
    defer a.free(marker);
    if (marker.len != 148 or !std.mem.eql(u8, marker[0..8], magic_marker) or
        readWord(marker[8..12]) != version or
        readWord(marker[12..16]) != statement.memory_instances.len or
        readWord(marker[16..20]) != plan.shards.len)
        return error.InvalidPublishedBlockMemoryRange;
    var channel = statement.seal.sharedChannel();
    const seal_digest = channel.digestBytes();
    if (!std.mem.eql(u8, marker[20..52], &seal_digest) or
        !std.mem.eql(u8, marker[52..84], &statement.seal.first_round_roster_digest) or
        !std.mem.eql(u8, marker[84..116], &statement.seal.range_shard_digest))
        return error.InvalidPublishedBlockMemoryRange;
    const memory_digests = try a.alloc(Digest, statement.memory_instances.len);
    defer a.free(memory_digests);
    const table_digests = try a.alloc(Digest, plan.shards.len);
    defer a.free(table_digests);
    for (memory_digests, 0..) |*item, i| {
        const name = try filename(a, "memory", @intCast(i));
        defer a.free(name);
        const raw = try dir.readFileAlloc(a, name, max_file_bytes);
        defer a.free(raw);
        item.* = digest(raw);
    }
    for (table_digests, 0..) |*item, i| {
        const name = try filename(a, "table", @intCast(i));
        defer a.free(name);
        const raw = try dir.readFileAlloc(a, name, max_file_bytes);
        defer a.free(raw);
        item.* = digest(raw);
    }
    const expected = markerBytes(statement, memory_digests, table_digests);
    if (!std.mem.eql(u8, marker, &expected)) return error.PublishedBlockProofDigestMismatch;
    var loaded = try loadUnchecked(a, dir, statement, memory_digests, table_digests);
    defer loaded.deinit();
    try batch.verifyMemoryRangeOnly(Backend, a, statement, loaded.wire(), config);
}
