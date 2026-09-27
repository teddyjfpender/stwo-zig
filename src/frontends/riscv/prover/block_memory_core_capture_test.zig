//! Test-only capture of serialized memory and range proofs for a block core.
const std = @import("std");
const core = @import("stwo_core");
const postcard = @import("interop_postcard");
const Replay = @import("block_memory_replay.zig").Replay;
const producer = @import("block_memory_batch_produce_v2.zig");
const batch = @import("block_memory_batch_verify_v2.zig");
const table = @import("block_memory_shared_table_proof_v2.zig");

pub const Source = struct {
    replay: *Replay,
    fn open(context: *anyopaque) anyerror!@import("../air/block/memory_transition.zig").Reader {
        const self: *Source = @ptrCast(@alignCast(context));
        return self.replay.reopenSortedTransitions();
    }
    pub fn asSource(self: *Source) producer.SortedSource {
        return .{ .context = self, .open = open };
    }
};

pub const Capture = struct {
    a: std.mem.Allocator,
    memories: []batch.SerializedMemoryProof,
    tables: []batch.SerializedTableProof,
    bytes: std.ArrayList([]u8) = .empty,
    next_memory: usize = 0,
    next_table: usize = 0,
    pub fn init(a: std.mem.Allocator, memory_count: usize, table_count: usize) !Capture {
        const memories = try a.alloc(batch.SerializedMemoryProof, memory_count);
        errdefer a.free(memories);
        return .{ .a = a, .memories = memories, .tables = try a.alloc(batch.SerializedTableProof, table_count) };
    }
    pub fn deinit(self: *Capture) void {
        for (self.bytes.items) |item| self.a.free(item);
        self.bytes.deinit(self.a);
        self.a.free(self.memories);
        self.a.free(self.tables);
    }
    pub fn sink(self: *Capture) producer.ProofSink {
        return .{ .context = self, .write_memory = onMemory, .write_table = onTable };
    }
    pub fn encode(self: *Capture, proof: core.proof_suites.Blake3.Proof) ![]u8 {
        var out = std.Io.Writer.Allocating.init(self.a);
        defer out.deinit();
        try postcard.serializeProof(core.proof_suites.Blake3.Hasher, &out.writer, proof);
        const owned = try self.a.dupe(u8, out.written());
        try self.bytes.append(self.a, owned);
        return owned;
    }
    fn onMemory(context: *anyopaque, index: u32, _: @import("../air/block/memory_component.zig").Claim, proof: *const @import("block_memory_shared_instance_proof_v2.zig").Proof) anyerror!void {
        const self: *Capture = @ptrCast(@alignCast(context));
        if (index != self.next_memory or index >= self.memories.len) return error.InvalidCaptureOrder;
        self.memories[index] = .{ .stark_bytes = try self.encode(proof.stark), .interaction_claim = proof.relation, .range_claims = proof.range_claims };
        self.next_memory += 1;
    }
    fn onTable(context: *anyopaque, _: @import("block_memory_range_shard_v2.zig").Shard, proof: *const table.Proof) anyerror!void {
        const self: *Capture = @ptrCast(@alignCast(context));
        if (self.next_memory != self.memories.len or self.next_table >= self.tables.len) return error.InvalidCaptureOrder;
        self.tables[self.next_table] = .{ .stark_bytes = try self.encode(proof.stark), .claim = proof.claim };
        self.next_table += 1;
    }
};
