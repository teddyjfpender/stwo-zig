//! Bounded in-memory serialized proof capture for a small block-v4 CPU batch.
//! Full blocks use staged files; this adapter qualifies the exact receiver
//! wire and measures its bytes without retaining live PCS proof objects.
const std = @import("std");
const core = @import("stwo_core");
const postcard = @import("interop_postcard");
const batch = @import("block_memory_batch_verify_v2.zig");
const producer = @import("block_memory_batch_produce_v2.zig");
const table = @import("block_memory_shared_table_proof_v2.zig");

pub const Capture = struct {
    a: std.mem.Allocator,
    memory: []batch.SerializedMemoryProof,
    tables: []batch.SerializedTableProof,
    bytes: std.ArrayList([]u8) = .empty,
    next_memory: usize = 0,
    next_table: usize = 0,
    total_bytes: u64 = 0,

    pub fn init(a: std.mem.Allocator, memory_count: usize, table_count: usize) !Capture {
        if (memory_count == 0 or table_count == 0) return error.EmptySmallBlockProofBatch;
        const memory = try a.alloc(batch.SerializedMemoryProof, memory_count);
        errdefer a.free(memory);
        return .{ .a = a, .memory = memory, .tables = try a.alloc(batch.SerializedTableProof, table_count) };
    }
    pub fn deinit(self: *Capture) void {
        for (self.bytes.items) |item| self.a.free(item);
        self.bytes.deinit(self.a);
        self.a.free(self.memory);
        self.a.free(self.tables);
        self.* = undefined;
    }
    pub fn sink(self: *Capture) producer.ProofSink {
        return .{ .context = self, .write_memory = onMemory, .write_table = onTable };
    }
    pub fn encode(self: *Capture, proof: core.proof_suites.Blake3.Proof) ![]u8 {
        var out = std.Io.Writer.Allocating.init(self.a);
        defer out.deinit();
        try postcard.serializeProof(core.proof_suites.Blake3.Hasher, &out.writer, proof);
        if (out.written().len == 0 or out.written().len > batch.MAX_STARK_BYTES)
            return error.SmallBlockProofTooLarge;
        const owned = try self.a.dupe(u8, out.written());
        errdefer self.a.free(owned);
        try self.bytes.append(self.a, owned);
        self.total_bytes = try std.math.add(u64, self.total_bytes, owned.len);
        return owned;
    }
    fn onMemory(context: *anyopaque, index: u32, _: @import("../air/block/memory_component.zig").Claim, proof: *const @import("block_memory_shared_instance_proof_v2.zig").Proof) anyerror!void {
        const self: *Capture = @ptrCast(@alignCast(context));
        if (index != self.next_memory or index >= self.memory.len or self.next_table != 0)
            return error.InvalidSmallBlockCaptureOrder;
        self.memory[index] = .{ .stark_bytes = try self.encode(proof.stark), .interaction_claim = proof.relation, .range_claims = proof.range_claims };
        self.next_memory += 1;
    }
    fn onTable(context: *anyopaque, shard: @import("block_memory_range_shard_v2.zig").Shard, proof: *const table.Proof) anyerror!void {
        const self: *Capture = @ptrCast(@alignCast(context));
        if (self.next_memory != self.memory.len or shard.index != self.next_table or
            self.next_table >= self.tables.len) return error.InvalidSmallBlockCaptureOrder;
        self.tables[self.next_table] = .{ .stark_bytes = try self.encode(proof.stark), .claim = proof.claim };
        self.next_table += 1;
    }
};
