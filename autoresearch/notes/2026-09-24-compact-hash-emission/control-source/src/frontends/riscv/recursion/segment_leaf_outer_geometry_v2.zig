//! Native-independent admission for the two SegmentV2 boundary components.
const std = @import("std");
const air_v2 = @import("segment_leaf_outer_air_v2.zig");
const layout = @import("segment_leaf_layout_v2.zig");
pub const Sha256Digest = [32]u8;
pub const NativeDigest = [8]u32;
pub const Error = error{InvalidManifest};
pub const COMPONENT_COUNT: u8 = 2;
pub const PUBLIC_LOGUP_LOGICAL_ROWS: u32 = layout.LOGUP_PUBLICATION_WORD_COUNT;
pub const PUBLIC_LOGUP_TRACE_LOG_SIZE: u8 = 6;
pub const PUBLIC_LOGUP_TRACE_ROWS: u32 = 1 << PUBLIC_LOGUP_TRACE_LOG_SIZE;
pub const STATEMENT_COMPONENT_TAG: u32 = 0x5332_5354;
pub const PUBLIC_LOGUP_COMPONENT_TAG: u32 = 0x5332_4c55;

pub const ComponentKindV2 = enum(u8) {
    statement_source = 0,
    public_logup_source = 1,
};

pub const ComponentGeometryV2 = struct {
    kind: ComponentKindV2,
    component_tag: u32,
    logical_rows: u32,
    trace_log_size: u8,
    trace_rows: u32,
    preprocessed_columns: u16,
    main_columns: u16,
    interaction_columns: u16,
    direct_constraints: u16,
    interaction_batches: u16,
    protocol_constraint_degree: u8,
    semantic_digest: Sha256Digest,

    pub fn validate(self: ComponentGeometryV2) Error!void {
        if (self.logical_rows == 0 or self.trace_log_size >= 31 or
            self.trace_rows != @as(u32, 1) << @intCast(self.trace_log_size) or
            self.trace_rows < self.logical_rows or
            (self.trace_log_size != 0 and
                self.trace_rows / 2 >= self.logical_rows))
        {
            return error.InvalidManifest;
        }
        switch (self.kind) {
            .statement_source => {
                if (self.component_tag != STATEMENT_COMPONENT_TAG or
                    self.preprocessed_columns !=
                        air_v2.Statement.PREPROCESSED_COLUMN_COUNT or
                    self.main_columns !=
                        air_v2.Statement.PHYSICAL_MAIN_COLUMN_COUNT or
                    self.interaction_columns !=
                        air_v2.Statement.INTERACTION_COLUMN_COUNT or
                    self.direct_constraints !=
                        air_v2.Statement.DIRECT_CONSTRAINT_COUNT or
                    self.interaction_batches !=
                        air_v2.Statement.INTERACTION_BATCH_COUNT or
                    self.protocol_constraint_degree !=
                        air_v2.Statement.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE or
                    !std.mem.eql(
                        u8,
                        &self.semantic_digest,
                        &air_v2.Statement.SEMANTIC_DIGEST,
                    ))
                {
                    return error.InvalidManifest;
                }
            },
            .public_logup_source => {
                if (self.component_tag != PUBLIC_LOGUP_COMPONENT_TAG or
                    self.logical_rows != PUBLIC_LOGUP_LOGICAL_ROWS or
                    self.trace_log_size != PUBLIC_LOGUP_TRACE_LOG_SIZE or
                    self.trace_rows != PUBLIC_LOGUP_TRACE_ROWS or
                    self.preprocessed_columns !=
                        air_v2.PublicLogUp.PREPROCESSED_COLUMN_COUNT or
                    self.main_columns !=
                        air_v2.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT or
                    self.interaction_columns !=
                        air_v2.PublicLogUp.INTERACTION_COLUMN_COUNT or
                    self.direct_constraints !=
                        air_v2.PublicLogUp.DIRECT_CONSTRAINT_COUNT or
                    self.interaction_batches !=
                        air_v2.PublicLogUp.INTERACTION_BATCH_COUNT or
                    self.protocol_constraint_degree !=
                        air_v2.PublicLogUp.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE or
                    !std.mem.eql(
                        u8,
                        &self.semantic_digest,
                        &air_v2.PublicLogUp.SEMANTIC_DIGEST,
                    ))
                {
                    return error.InvalidManifest;
                }
            },
        }
    }
};
