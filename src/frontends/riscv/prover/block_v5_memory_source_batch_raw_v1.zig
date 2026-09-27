//! B5SF canonical raw source scheduling. This API cannot request a sibling
//! path: only the four writer files and public input may be read. File SHA
//! checks and witness scheduling are proposals, never source proof authority.
const std = @import("std");
const core = @import("stwo_core");
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
const Batch = @import("block_v5_memory_source_batch_protocol_v1.zig");
const Fold = @import("block_v5_memory_source_batch_fold_v1.zig");
const Writer = @import("block_v5_memory_source_writer_v1.zig");
const Initial = @import("block_v5_initial_sources_v1.zig");
const Eq = @import("../recursion/air/block_v5_memory_source_equations_v1.zig");
const Indexed = @import("../recursion/air/block_v5_memory_source_batch_equations_v1.zig");
const SHA = @import("block_v5_memory_source_packed_sha_v1.zig");
const Compression = @import("../air/guest_precompile/sha256_compression.zig");
pub const Reader = Fold.Reader;
pub const Descriptor = union(enum) {
    sha: struct { stream: Source.Stream, block: u64 },
    record: struct { stream: Source.Stream, ordinal: u64 },
    pub fn original(self: Descriptor) Eq.Kind {
        return switch (self) {
            .sha => |s| .{ .sha = .{ .stream = s.stream, .block = s.block } },
            .record => |r| .{ .record = .{ .stream = r.stream, .ordinal = r.ordinal } },
        };
    }
};
pub const Census = struct { sha_chunks: u64, compressions: u64, records: u64, total: u64 };
pub fn census(admitted: *const Source.Admitted) !Census {
    try admitted.require();
    var out = Census{ .sha_chunks = 0, .compressions = 0, .records = 0, .total = 0 };
    inline for (std.meta.tags(Source.Stream)) |stream| {
        out.sha_chunks = try std.math.add(u64, out.sha_chunks, admitted.byteLength(stream) / 64 + 1);
        out.compressions = try std.math.add(u64, out.compressions, try SHA.compressionCount(admitted.byteLength(stream)));
        if (stream != .public_input) out.records = try std.math.add(u64, out.records, admitted.records(stream));
    }
    // Core call IDs are independently reconstructed public field elements.
    if (out.compressions + 1 >= core.fields.m31.Modulus) return error.SourceBatchCoreCensusLimit;
    out.total = try std.math.add(u64, out.sha_chunks, out.records);
    return out;
}
pub fn kindAt(admitted: *const Source.Admitted, ordinal: u64) !Descriptor {
    if (ordinal >= (try census(admitted)).total) return error.InvalidSourceBatchRawOrdinal;
    var remaining = ordinal;
    inline for (std.meta.tags(Source.Stream)) |stream| {
        const count = admitted.byteLength(stream) / 64 + 1;
        if (remaining < count) return .{ .sha = .{ .stream = stream, .block = remaining } };
        remaining -= count;
    }
    inline for (.{ Source.Stream.input_words, Source.Stream.rw_words, Source.Stream.first_touches, Source.Stream.endpoints }) |stream| {
        const count = admitted.records(stream);
        if (remaining < count) return .{ .record = .{ .stream = stream, .ordinal = remaining } };
        remaining -= count;
    }
    return error.InvalidSourceBatchRawOrdinal;
}
pub fn firstCall(admitted: *const Source.Admitted, stream: Source.Stream, block: u64) !u32 {
    _ = try census(admitted);
    _ = try SHA.chunkCompressionCount(admitted, stream, block);
    var first: u64 = 1;
    inline for (std.meta.tags(Source.Stream)) |candidate| {
        if (candidate == stream) return @intCast(first + block);
        first += try SHA.compressionCount(admitted.byteLength(candidate));
    }
    return error.InvalidSourceBatchRawOrdinal;
}
pub fn recordSize(stream: Source.Stream) !usize {
    return switch (stream) {
        .input_words, .rw_words => 8,
        .first_touches => 9,
        .endpoints => 16,
        .public_input => error.InvalidSourceBatchRawRecord,
    };
}
pub const Chunk = struct { ordinal: u64, descriptor: Descriptor, witness: Eq.Witness };
pub const Cursor = struct {
    admission: Batch.Admission,
    reader: Reader,
    expected: Census,
    emitted: u64 = 0,
    previous_stream: ?Source.Stream = null,
    previous_address: u32 = 0,
    state: Compression.State = Compression.initial_state,
    pub fn init(admission: Batch.Admission, reader: Reader) !Cursor {
        try admission.require();
        return .{ .admission = admission, .reader = reader, .expected = try census(&admission.source) };
    }
    pub fn next(self: *Cursor) !?Chunk {
        if (self.emitted == self.expected.total) return null;
        const descriptor = try kindAt(&self.admission.source, self.emitted);
        var witness = Eq.Witness{};
        switch (descriptor) {
            .sha => |s| {
                if (s.block == 0) self.state = Compression.initial_state;
                witness.state = self.state;
                const length = self.admission.source.byteLength(s.stream);
                const terminal = s.block == length / 64;
                const used: usize = if (terminal) @intCast(length % 64) else 64;
                if (used != 0) try self.reader.read(self.reader.context, s.stream, s.block * 64, witness.raw[0..used]);
                if (!terminal) self.state = Compression.compress(self.state, witness.raw);
            },
            .record => |r| {
                const size = try recordSize(r.stream);
                var bytes: [16]u8 = @splat(0);
                try self.reader.read(self.reader.context, r.stream, r.ordinal * size, bytes[0..size]);
                if (self.previous_stream == null or self.previous_stream.? != r.stream) self.previous_address = 0;
                witness.previous_address = self.previous_address;
                switch (r.stream) {
                    .input_words, .rw_words => {
                        witness.address = std.mem.readInt(u32, bytes[0..4], .little);
                        witness.after = std.mem.readInt(u32, bytes[4..8], .little);
                    },
                    .first_touches => {
                        if (bytes[0] != 1) return error.InvalidSourceBatchRawRamSpace;
                        witness.address = std.mem.readInt(u32, bytes[1..5], .little);
                        witness.before = std.mem.readInt(u32, bytes[5..9], .little);
                    },
                    .endpoints => {
                        witness.address = std.mem.readInt(u32, bytes[0..4], .little);
                        witness.clock = std.mem.readInt(u64, bytes[4..12], .little);
                        witness.after = std.mem.readInt(u32, bytes[12..16], .little);
                    },
                    .public_input => unreachable,
                }
                if (r.ordinal != 0 and witness.address <= self.previous_address) return error.InvalidSourceBatchRawRecordOrder;
                self.previous_stream = r.stream;
                self.previous_address = witness.address;
            },
        }
        const out = Chunk{ .ordinal = self.emitted, .descriptor = descriptor, .witness = witness };
        self.emitted += 1;
        return out;
    }
};
/// Borrowed files/public input. Result owner must outlive every read; this
/// object neither closes files nor turns host file checks into a receipt.
pub const Files = struct {
    result: *const Writer.Result,
    public_input: []const u8,
    admitted: Source.Admitted,
    pub fn init(result: *const Writer.Result, public_input: []const u8, admitted: Source.Admitted) !Files {
        try admitted.require();
        if (result.register_custody_mode != 1 or std.mem.allEqual(u8, &result.register_window_plan_digest, 0)) return error.InvalidSourceBatchRawRegisterMode;
        if (!std.meta.eql(result.initial_pins, admitted.pins.initial) or !std.meta.eql(result.endpoint_file_pin, admitted.pins.endpoints) or !std.meta.eql(result.final_rw_root, admitted.pins.expected_final_rw_root) or public_input.len != admitted.byteLength(.public_input) or !std.meta.eql(Initial.sha256(public_input), admitted.digest(.public_input))) return error.InvalidSourceBatchRawFiles;
        inline for (.{ Source.Stream.input_words, Source.Stream.rw_words, Source.Stream.first_touches, Source.Stream.endpoints }, 0..) |stream, i| {
            if (try result.opened[i].getEndPos() != admitted.byteLength(stream)) return error.InvalidSourceBatchRawFileLength;
        }
        return .{ .result = result, .public_input = public_input, .admitted = admitted };
    }
    pub fn reader(self: *Files) Reader {
        return .{ .context = self, .read = read };
    }
    fn read(context: *anyopaque, stream: Source.Stream, offset: u64, dst: []u8) !void {
        const self: *Files = @ptrCast(@alignCast(context));
        const length = self.admitted.byteLength(stream);
        if (offset > length or dst.len > length - offset) return error.InvalidSourceBatchRawOffset;
        if (stream == .public_input) {
            @memcpy(dst, self.public_input[@intCast(offset)..][0..dst.len]);
        } else {
            const file_index: usize = @intFromEnum(stream) - 2;
            if (try self.result.opened[file_index].preadAll(dst, offset) != dst.len) return error.InvalidSourceBatchRawFileLength;
        }
    }
};
pub fn Algebra(comptime S: type) type {
    return struct {
        const Original = Eq.Algebra(S);
        const BatchEq = Indexed.Algebra(S);
        pub const Sums = struct { source: Original.Sums, indexed: S };
        /// Original record equations consume the SAME committed private cells
        /// as indexed13 supplies. No host decode/sum or descriptor is authority.
        pub fn record(admitted: *const Source.Admitted, descriptor: Descriptor, inputs: []const S, indexed: BatchEq.Pair, sink: anytype) !Sums {
            const record_desc = switch (descriptor) {
                .record => |value| value,
                .sha => return error.InvalidSourceBatchRawRecord,
            };
            const source = try Original.compute(admitted, descriptor.original(), inputs, sink);
            return .{ .source = source, .indexed = try BatchEq.indexedRecord(record_desc.stream, record_desc.ordinal, inputs, indexed) };
        }
    };
}
