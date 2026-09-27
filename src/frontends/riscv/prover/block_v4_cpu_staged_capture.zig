//! File-backed proof sink: one live STARK at a time during memory production.
const std = @import("std");
const core = @import("stwo_core");
const postcard = @import("interop_postcard");
const batch = @import("block_memory_batch_verify_v2.zig");
const producer = @import("block_memory_batch_produce_v2.zig");
const table = @import("block_memory_shared_table_proof_v2.zig");
const memory = @import("../air/block/memory_component.zig");
const range = @import("../air/block/memory_range_interaction_v2.zig");

pub const Entry = struct { len: u64, sha256: [32]u8 };
pub const MemoryMeta = struct {
    file: Entry,
    relation: @import("block_memory_relation_v2.zig").ComponentClaim,
    ranges: range.Claims,
};
pub const TableMeta = struct {
    file: Entry,
    claim: core.fields.qm31.QM31,
};

pub const Loaded = struct {
    a: std.mem.Allocator,
    memory: []batch.SerializedMemoryProof,
    tables: []batch.SerializedTableProof,
    pub fn deinit(self: *Loaded) void {
        for (self.memory) |wire| self.a.free(wire.stark_bytes);
        for (self.tables) |wire| self.a.free(wire.stark_bytes);
        self.a.free(self.memory);
        self.a.free(self.tables);
        self.* = undefined;
    }
};

pub const Capture = struct {
    a: std.mem.Allocator,
    dir: std.fs.Dir,
    memory: []MemoryMeta,
    tables: []TableMeta,
    extra: std.ArrayList([]u8) = .empty,
    next_memory: usize = 0,
    next_table: usize = 0,
    total_bytes: u64 = 0,

    pub fn init(a: std.mem.Allocator, dir: std.fs.Dir, memory_count: usize, table_count: usize) !Capture {
        if (memory_count == 0 or table_count == 0) return error.EmptyBlockProofBatch;
        const memories = try a.alloc(MemoryMeta, memory_count);
        errdefer a.free(memories);
        return .{ .a = a, .dir = dir, .memory = memories, .tables = try a.alloc(TableMeta, table_count) };
    }
    pub fn deinit(self: *Capture) void {
        for (self.extra.items) |bytes| self.a.free(bytes);
        self.extra.deinit(self.a);
        self.a.free(self.memory);
        self.a.free(self.tables);
        self.* = undefined;
    }
    pub fn sink(self: *Capture) producer.ProofSink {
        return .{ .context = self, .write_memory = onMemory, .write_table = onTable };
    }
    pub fn load(self: *Capture) !Loaded {
        if (self.next_memory != self.memory.len or self.next_table != self.tables.len)
            return error.IncompleteStagedBlockProof;
        const memories = try self.a.alloc(batch.SerializedMemoryProof, self.memory.len);
        errdefer self.a.free(memories);
        const tables = try self.a.alloc(batch.SerializedTableProof, self.tables.len);
        errdefer self.a.free(tables);
        var loaded_memory: usize = 0;
        var loaded_table: usize = 0;
        errdefer {
            for (memories[0..loaded_memory]) |wire| self.a.free(wire.stark_bytes);
            for (tables[0..loaded_table]) |wire| self.a.free(wire.stark_bytes);
        }
        for (self.memory, memories, 0..) |meta, *wire, i| {
            wire.* = .{ .stark_bytes = try self.read(.memory, i, meta.file), .interaction_claim = meta.relation, .range_claims = meta.ranges };
            loaded_memory += 1;
        }
        for (self.tables, tables, 0..) |meta, *wire, i| {
            wire.* = .{ .stark_bytes = try self.read(.table, i, meta.file), .claim = meta.claim };
            loaded_table += 1;
        }
        return .{ .a = self.a, .memory = memories, .tables = tables };
    }
    /// Incremental receiver entry point. Each returned byte slice is owned by
    /// the caller and must be freed before opening the next memory proof.
    pub fn loadMemory(self: *Capture, index: usize) !batch.SerializedMemoryProof {
        if (self.next_memory != self.memory.len or self.next_table != self.tables.len or
            index >= self.memory.len) return error.IncompleteStagedBlockProof;
        const meta = self.memory[index];
        return .{ .stark_bytes = try self.read(.memory, index, meta.file),
            .interaction_claim = meta.relation, .range_claims = meta.ranges };
    }
    /// As with `loadMemory`, release `stark_bytes` after fresh verification.
    pub fn loadTable(self: *Capture, index: usize) !batch.SerializedTableProof {
        if (self.next_memory != self.memory.len or self.next_table != self.tables.len or
            index >= self.tables.len) return error.IncompleteStagedBlockProof;
        const meta = self.tables[index];
        return .{ .stark_bytes = try self.read(.table, index, meta.file), .claim = meta.claim };
    }
    /// Execution range tables are few; retain these postcard bytes in memory
    /// for the final receiver while the larger sorted-memory proofs stay staged.
    pub fn encode(self: *Capture, proof: core.proof_suites.Blake3.Proof) ![]u8 {
        const bytes = try serialize(self.a, proof);
        errdefer self.a.free(bytes);
        try self.extra.append(self.a, bytes);
        self.total_bytes = try std.math.add(u64, self.total_bytes, bytes.len);
        return bytes;
    }
    fn onMemory(context: *anyopaque, index: u32, _: memory.Claim, proof: *const @import("block_memory_shared_instance_proof_v2.zig").Proof) anyerror!void {
        const self: *Capture = @ptrCast(@alignCast(context));
        if (index != self.next_memory or self.next_table != 0 or index >= self.memory.len)
            return error.InvalidStagedBlockProofOrder;
        self.memory[index] = .{ .file = try self.write(.memory, index, proof.stark), .relation = proof.relation, .ranges = proof.range_claims };
        self.next_memory += 1;
    }
    fn onTable(context: *anyopaque, part: @import("block_memory_range_shard_v2.zig").Shard, proof: *const table.Proof) anyerror!void {
        const self: *Capture = @ptrCast(@alignCast(context));
        if (self.next_memory != self.memory.len or part.index != self.next_table or
            self.next_table >= self.tables.len) return error.InvalidStagedBlockProofOrder;
        self.tables[self.next_table] = .{ .file = try self.write(.table, self.next_table, proof.stark), .claim = proof.claim };
        self.next_table += 1;
    }
    const Kind = enum { memory, table };
    fn name(kind: Kind, index: usize, buffer: *[80]u8) ![]const u8 {
        return std.fmt.bufPrint(buffer, "block-v4-{s}-{d}.stark", .{ @tagName(kind), index });
    }
    fn write(self: *Capture, kind: Kind, index: usize, proof: core.proof_suites.Blake3.Proof) !Entry {
        const bytes = try serialize(self.a, proof);
        defer self.a.free(bytes);
        var buffer: [80]u8 = undefined;
        const path = try name(kind, index, &buffer);
        var file = try self.dir.createFile(path, .{ .exclusive = true, .read = true });
        defer file.close();
        try file.writeAll(bytes);
        try file.sync();
        self.total_bytes = try std.math.add(u64, self.total_bytes, bytes.len);
        return .{ .len = bytes.len, .sha256 = sha(bytes) };
    }
    fn read(self: *Capture, kind: Kind, index: usize, expected: Entry) ![]u8 {
        if (expected.len == 0 or expected.len > batch.MAX_STARK_BYTES)
            return error.InvalidStagedBlockProofSize;
        var buffer: [80]u8 = undefined;
        const path = try name(kind, index, &buffer);
        var file = try self.dir.openFile(path, .{});
        defer file.close();
        const bytes = try file.readToEndAlloc(self.a, @intCast(expected.len));
        errdefer self.a.free(bytes);
        if (bytes.len != expected.len or
            !std.mem.eql(u8, &sha(bytes), &expected.sha256))
            return error.ChangedStagedBlockProof;
        return bytes;
    }
};

fn serialize(a: std.mem.Allocator, proof: core.proof_suites.Blake3.Proof) ![]u8 {
    var writer = std.Io.Writer.Allocating.init(a);
    defer writer.deinit();
    try postcard.serializeProof(core.proof_suites.Blake3.Hasher, &writer.writer, proof);
    if (writer.written().len == 0 or writer.written().len > batch.MAX_STARK_BYTES)
        return error.StagedBlockProofTooLarge;
    return a.dupe(u8, writer.written());
}

fn sha(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}
