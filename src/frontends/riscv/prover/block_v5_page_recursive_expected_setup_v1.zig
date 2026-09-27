//! Independent PAGE setup and live parity guards. Semantic constants originate
//! in the pinned pre-proof policy, never in a decoded proof or verified token.
const std = @import("std");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const ClaimsPolicy = @import("block_v5_memory_source_page_policy_file_v1.zig");
const Fixed = @import("../recursion/block_v5_memory_source_page_recursive_fixed_roster_v1.zig");
const Storage = @import("../recursion/air/blake3_parent_row_storage.zig");
const FixedKey = @import("../recursion/blake3_parent_fixed_key_v1.zig");
const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
pub const Limits = Fixed.Limits;
pub fn requireClaims(comptime kind: Semantic.Kind, expected: Semantic.Claims, actual: Semantic.Claims) !void {
    _ = try ClaimsPolicy.expectedClaims(kind, expected);
    _ = try ClaimsPolicy.expectedClaims(kind, actual);
    if (!std.meta.eql(expected, actual)) return error.UntrustedPagePolicySemanticClaims;
}
/// Independently derived VERSION16 setup metadata. The actual producer still
/// admits its live preprocessed root through the original shared Plan kernel.
pub fn requireNodeMetadata(geometry: Base.Key, context: Base.Context, logs: [Storage.Airs.len]u32, wires: []const @import("../recursion/block_v5_memory_source_page_forest_bus_v1.zig").Wire) !void {
    if (wires.len != 0 or !std.meta.eql(geometry.context, context) or !std.meta.eql(geometry.log_sizes, logs)) return error.UntrustedPageExpectedSetup;
}
pub fn ForKind(comptime kind: Semantic.Kind) type {
    const Bus = @import("../recursion/block_v5_memory_source_page_recursive_public_bus_v1.zig").ForKind(kind);
    const Protocol = @import("../recursion/block_v5_reusable_memory_source_page_parent_protocol_v1.zig").ForKind(kind);
    const Admission = @import("block_v5_memory_source_page_recursive_admission_v1.zig").ForKind(kind);
    return struct {
        pub fn requireMetadata(key: Protocol.Key, context: Base.Context, logs: [Storage.Airs.len]u32, wires: []const Bus.Wire) !void {
            if (!std.meta.eql(key.context, context) or !std.meta.eql(key.log_sizes, logs) or
                !std.meta.eql(try Bus.scheduleDigest(wires), key.public_schedule_digest)) return error.UntrustedPageExpectedSetup;
        }
        /// Producer Plan.init independently commits the live fixed rows and
        /// admits the ORIGINAL expected root after these exact routing checks.
        /// Cached proving additionally checks the independently expected key
        /// immediately after its acquire and before any proving work.
        pub fn requirePrepared(key: Protocol.Key, expected_wires: []const Bus.Wire, rows: *Bus.Prepared) !void {
            try rows.recursive.rows.partitionHashRows();
            try requireMetadata(key, rows.recursive.context, try FixedKey.rowLogs(rows.recursive.rows.fixed), rows.wires);
            if (expected_wires.len != rows.wires.len) return error.UntrustedPageExpectedSetup;
            for (expected_wires, rows.wires) |expected, actual| if (!std.meta.eql(expected, actual)) return error.UntrustedPageExpectedSetup;
        }
        pub fn ForBackend(comptime Backend: type) type {
            const Factory = Fixed.ForKind(kind).ForBackend(Backend);
            return struct {
                pub const Expected = Factory.KeyAndSchedule;
                /// Scratch fixed columns disappear before this returns. The
                /// resulting key/schedule are borrowed synchronously from the
                /// returned owner; no capture, MAIN or private proof is read.
                pub fn derive(a: std.mem.Allocator, admitted: *const Admission.Prepared, claims: Semantic.Claims, capacity: u32, profile: Base.Profile, limits: Limits) !Expected {
                    _ = try ClaimsPolicy.expectedClaims(kind, claims);
                    return Factory.deriveKeyAndScheduleForPolicy(a, admitted, admitted.template_id, claims, capacity, profile, limits);
                }
            };
        }
    };
}
