//! Publication-provider shape derived only from admitted claim count.
const std = @import("std");
const leaf_source = @import("../segment_leaf_layout_v2.zig");
pub const Error = error{ InvalidInputPair, InvalidPreparedSource };
pub const FORMAT_VERSION: u16 = 3;
pub const SCHEMA_VERSION: u16 = 1;
pub const PROPOSED_ROSTER_ROW: u8 = 38;
pub const LUP2_WORD_COUNT: usize = leaf_source.LOGUP_PUBLICATION_WORD_COUNT;
pub const SECURE_LIMB_COUNT: usize = 4;

pub const Shape = struct {
    claim_count: u32,
    logical_row_count: u32,
    trace_log_size: u32,

    pub fn init(claim_count: usize) Error!Shape {
        if (claim_count == 0) return error.InvalidInputPair;
        const limbs = std.math.mul(usize, claim_count, SECURE_LIMB_COUNT) catch
            return error.InvalidInputPair;
        const rows = std.math.add(usize, LUP2_WORD_COUNT, limbs) catch
            return error.InvalidInputPair;
        if (rows > (1 << 30)) return error.InvalidInputPair;
        return .{
            .claim_count = @intCast(claim_count),
            .logical_row_count = @intCast(rows),
            .trace_log_size = std.math.log2_int_ceil(u32, @intCast(rows)),
        };
    }

    pub fn validate(self: Shape) Error!void {
        if (!std.meta.eql(self, try init(self.claim_count)))
            return error.InvalidPreparedSource;
    }

    pub fn traceRowCount(self: Shape) usize {
        return @as(usize, 1) << @intCast(self.trace_log_size);
    }
};

/// Frozen small-fixture geometry. Live captures use PreparedV2.shape.
pub const DETAILED_CLAIM_COUNT: usize = 21;
pub const LEGACY_SHAPE = Shape.init(DETAILED_CLAIM_COUNT) catch unreachable;
pub const DETAILED_LIMB_COUNT = DETAILED_CLAIM_COUNT * SECURE_LIMB_COUNT;
pub const LOGICAL_ROW_COUNT = LEGACY_SHAPE.logical_row_count;
pub const TRACE_LOG_SIZE = LEGACY_SHAPE.trace_log_size;
pub const TRACE_ROW_COUNT = LEGACY_SHAPE.traceRowCount();
pub const ACTIVE_RELATION_EVENT_COUNT = LOGICAL_ROW_COUNT;
