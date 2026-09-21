//! Authenticated selector for a verified temporal child's prover transcript.
//!
//! The height-1 parent cohort and the recursively closed node cohort share a
//! proof/publication shape but mix different authority frames. This descriptor
//! is retained in both verifier publication and artifact custody. Its kind is
//! checked against the authenticated child statement height before replay, so
//! proof data can never route itself to a transcript implementation.

const std = @import("std");

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const COMPONENT_COUNT: u16 = 36;

pub const Kind = enum(u8) {
    temporal_parent_v3 = 1,
    recursive_node_v1 = 2,
    empty_parent_v1 = 3,
};

pub const DescriptorV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    kind: Kind,
    padding: [3]u8 = .{ 0, 0, 0 },
    domain: u32,
    cohort_format_version: u16,
    cohort_schema_version: u16,
    component_count: u16 = COMPONENT_COUNT,
    reserved: u16 = 0,

    pub fn temporalParentV3() DescriptorV1 {
        return canonical(.temporal_parent_v3);
    }

    pub fn recursiveNodeV1() DescriptorV1 {
        return canonical(.recursive_node_v1);
    }

    pub fn emptyParentV1() DescriptorV1 {
        return canonical(.empty_parent_v1);
    }

    pub fn validate(self: DescriptorV1) !void {
        if (!std.meta.eql(self, canonical(self.kind)))
            return error.InvalidChildTranscriptAuthority;
    }

    pub fn validateForChildHeight(self: DescriptorV1, height: u8) !void {
        try self.validate();
        if (height == 0 or (height == 1 and
            self.kind != .temporal_parent_v3 and
            self.kind != .empty_parent_v1) or
            (height > 1 and self.kind != .recursive_node_v1))
        {
            return error.ChildTranscriptAuthorityMismatch;
        }
    }

    /// Schema-1 publications predate this descriptor. Keeping their exact
    /// canonical parent frame on the legacy identity path preserves every
    /// existing height-2 publication/artifact identity byte-for-byte.
    pub fn isLegacyParent(self: DescriptorV1) bool {
        return std.meta.eql(self, temporalParentV3());
    }
};

pub fn expectedForChildHeight(height: u8) !DescriptorV1 {
    if (height == 0) return error.InvalidTemporalChildHeight;
    return canonical(expectedKind(height));
}

pub fn expectedEmptyParent() DescriptorV1 {
    return canonical(.empty_parent_v1);
}

fn expectedKind(height: u8) Kind {
    return if (height == 1) .temporal_parent_v3 else .recursive_node_v1;
}

fn canonical(kind: Kind) DescriptorV1 {
    return switch (kind) {
        .temporal_parent_v3 => .{
            .kind = kind,
            .domain = 0x5450_4333, // "TPC3"
            .cohort_format_version = 3,
            .cohort_schema_version = 1,
        },
        .recursive_node_v1 => .{
            .kind = kind,
            .domain = 0x4c32_4331, // "L2C1"
            .cohort_format_version = 1,
            .cohort_schema_version = 1,
        },
        .empty_parent_v1 => .{
            .kind = kind,
            .domain = 0x4550_4331, // "EPC1"
            .cohort_format_version = 1,
            .cohort_schema_version = 1,
        },
    };
}

comptime {
    if (FORMAT_VERSION != 1 or SCHEMA_VERSION != 1 or COMPONENT_COUNT != 36 or
        std.meta.eql(DescriptorV1.temporalParentV3(), DescriptorV1.recursiveNodeV1()) or
        std.meta.eql(DescriptorV1.temporalParentV3(), DescriptorV1.emptyParentV1()) or
        std.meta.eql(DescriptorV1.recursiveNodeV1(), DescriptorV1.emptyParentV1()))
    {
        @compileError("temporal child transcript descriptor drifted");
    }
}
