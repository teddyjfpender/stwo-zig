//! Owning V2 exact-count cover of independently verified V1 dyadic proofs.
const std = @import("std");
const spans = @import("span_statement_blake3.zig");
const protocol = @import("blake3_exact_forest_protocol.zig");

pub fn ForNode(comptime Node: type) type {
    return struct {
        pub const protocol_version: u32 = protocol.VERSION;
        job: spans.JobContext,
        nodes: [spans.MAX_SLOT_HEIGHT + 1]Node = undefined,
        count: usize = 0,

        const Self = @This();
        pub fn deinit(self: *Self) void {
            for (self.nodes[0..self.count]) |*node| node.deinit();
            self.* = undefined;
        }

        /// Every member proof is verified before checking exact span closure.
        pub fn validate(self: *const Self) !spans.ExecutedSpan {
            if (self.count > self.nodes.len) return error.IncompleteStream;
            var entries: [spans.MAX_SLOT_HEIGHT + 1]protocol.Entry = undefined;
            for (self.nodes[0..self.count], 0..) |*node, index| {
                try node.validate();
                entries[index] = .{
                    .statement = node.statement,
                    .expected_key_id = if (comptime @hasField(Node, "admission")) node.admission.expected_id else @splat(0),
                };
            }
            return protocol.validate(self.job, entries[0..self.count]);
        }

        /// Identity of the verified roster; the digest alone is not a proof.
        pub fn rosterDigest(self: *const Self) ![32]u8 {
            _ = try self.validate();
            var entries: [spans.MAX_SLOT_HEIGHT + 1]protocol.Entry = undefined;
            for (self.nodes[0..self.count], 0..) |*node, index| {
                entries[index] = .{
                    .statement = node.statement,
                    .expected_key_id = if (comptime @hasField(Node, "admission")) node.admission.expected_id else @splat(0),
                };
            }
            return protocol.digest(self.job, entries[0..self.count]);
        }

        /// Producer gate before publishing a roster JSON: every advertised
        /// member must have its canonical proof body still owned in memory.
        pub fn validateTransportReady(self: *const Self) !void {
            _ = try self.validate();
            if (comptime @hasField(Node, "transport_bytes")) {
                for (self.nodes[0..self.count]) |*node| {
                    if (node.transport_bytes == null or node.transport_bytes.?.len == 0)
                        return error.ExactForestTransportUnavailable;
                }
            } else return error.ExactForestTransportUnavailable;
        }
    };
}
