//! Genuine distinct raw-page commitment/replay specialization. The census is
//! SHA+record only; no sibling chunk, path callback, or legacy B5SC relabel.
//! This low-level owner is not a source arithmetic proof. Its challenge API
//! must be integrated with a complete raw/fold/core roster before activation.
const std = @import("std");
const Raw = @import("block_v5_memory_source_batch_raw_v1.zig");
const Batch = @import("block_v5_memory_source_batch_protocol_v1.zig");
pub const TAG: u32 = 0x42355352; // B5SR
pub const VERSION: u32 = 1;
pub const FIXED_COUNT: usize = 15;
pub const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
pub const Equations = @import("../recursion/air/block_v5_memory_source_equations_v1.zig");
pub const MAIN_COUNT: usize = Equations.BIT_COUNT;
// Explicit bit-crypto parity oracle for the shared candidate preparation API.
// The actual packed page proof must use its same-main connector component;
// preparing this graph is not proof authority or the efficient producer.
pub const Circuit = @import("block_v5_memory_source_circuit_v1.zig");
pub const Reader = Raw.Reader;
pub const FILE_MAGIC = "B5SRRAW1";
pub const CompactCodec = @import("block_v5_memory_source_raw_operand_codec_v1.zig");
pub const FILE_VERSION: u32 = 1;
pub const writeBits = @import("block_v5_memory_source_witness_bits_v1.zig").writeBits;
pub const restoreBits = @import("block_v5_memory_source_witness_bits_v1.zig").restoreBits;
pub const fixedAt = @import("block_v5_memory_source_fixed_recipe_v1.zig").ForSchedule(Stream).fixedAt;
pub const Protocol = @import("block_v5_memory_source_first_protocol_common_v1.zig").ForSchema(@This());
pub const Columns = @import("block_v5_memory_source_first_columns_common_v1.zig").ForSchema(@This());
pub const Round = @import("block_v5_memory_source_first_round_common_v1.zig").ForSchema(@This());
pub const Store = @import("block_v5_memory_source_page_store_common_v1.zig").ForSchema(@This());
pub const Replay = @import("block_v5_memory_source_page_replay_common_v1.zig").ForSchema(@This());
pub const Stream = struct {
    pub const Chunk = struct { kind: Equations.Kind, witness: Equations.Witness };
    pub const Cursor = struct {
        inner: Raw.Cursor,
        emitted: u64 = 0,
        pub fn next(self: *Cursor) !?Chunk {
            const chunk = try self.inner.next() orelse return null;
            self.emitted = self.inner.emitted;
            return .{ .kind = chunk.descriptor.original(), .witness = chunk.witness };
        }
    };
    pub fn census(admitted: *const Source.Admitted) !Raw.Census {
        return Raw.census(admitted);
    }
    pub fn kindAt(admitted: *const Source.Admitted, ordinal: u64) !Equations.Kind {
        return (try Raw.kindAt(admitted, ordinal)).original();
    }
};
pub fn cursorInit(admitted: Source.Admitted, reader: Reader) !Stream.Cursor {
    return .{ .inner = try Raw.Cursor.init(try Batch.Admission.init(admitted, .{}), reader) };
}
pub fn cursorAdmission(cursor: *const Stream.Cursor) *const Source.Admitted {
    return &cursor.inner.admission.source;
}
pub fn abiId() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-v5/source-batch-raw-first/v1\x00");
    hash.update(&Batch.abiId());
    hash.update("B5SR;fixed15;main1728;SHA-five-raw-streams;indexed13-records;no-edit-opening;no-leaf-node-root-path-rows;exact-circle-order;zero-tail;LE-bits;durable-SHA96-record12-endpoint20;canonical-dropped-zero;no-source-authority\x00");
    return hash.finalResult();
}
