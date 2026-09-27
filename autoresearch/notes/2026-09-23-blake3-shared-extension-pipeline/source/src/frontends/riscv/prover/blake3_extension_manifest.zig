//! Authenticate extension and native metadata together before decoding.
pub fn ForProfile(comptime Profile: type) type {
    return struct {
        const std = @import("std");
        const core = @import("stwo_core");
        const base = @import("blake3_execution_manifest.zig");
        const native = @import("../air/statement.zig").Blake3ExecutionStatement;
        const plans = @import("blake3_commitment_plan.zig");
        const extension = Profile.admission;
        const extension_wire = Profile.ExtensionWire;
        pub const MAGIC = Profile.manifest_magic;
        pub const PREFIX_BYTES = 12 + extension_wire.extension_encoded_size;
        pub const HEADER_BYTES = PREFIX_BYTES + base.HEADER_BYTES;
        pub const Limits = base.Limits;
        pub const Source = base.Source;
        pub const identity = base.identity;
        pub const Owned = struct {
            base: base.Owned,
            extension: extension.Statement,
            pub fn deinit(self: *Owned) void {
                self.base.deinit();
                self.* = undefined;
            }
        };
        const Context = struct {
            extension: extension.Statement,
            pub fn validate(self: @This(), shape: *const native) !void {
                try shape.validateBlake3ExecutionWithExternal(Profile.externalCount(&self.extension));
                try Profile.validateGeometry(&self.extension, shape.total_steps);
            }
            pub fn mix(self: @This(), a: std.mem.Allocator, channel: anytype, config: core.pcs.PcsConfig, shape: *const native, pin: plans.Admission) !void {
                const logs = try @import("blake3_commitment_columns.zig").traceLogs(a, pin);
                try Profile.protocol.mix(channel, config, shape, &self.extension, pin, logs);
            }
        };
        pub fn encode(a: std.mem.Allocator, shape: *const native, ext: extension.Statement, pin: plans.Admission, config: core.pcs.PcsConfig, source: Source, limits: Limits) ![]u8 {
            const inner = try base.encodeWithContext(a, shape, pin, config, source, limits, Context{ .extension = ext });
            defer a.free(inner);
            const size = try std.math.add(usize, PREFIX_BYTES, inner.len);
            if (size > limits.max_bytes) return error.ExecutionManifestResourceLimit;
            const raw = try a.alloc(u8, size);
            errdefer a.free(raw);
            @memcpy(raw[0..8], MAGIC);
            std.mem.writeInt(u32, raw[8..12], 1, .little);
            var stream = std.io.fixedBufferStream(raw[12..PREFIX_BYTES]);
            try extension_wire.encodeExtension(stream.writer(), &ext);
            std.debug.assert(stream.pos == extension_wire.extension_encoded_size);
            @memcpy(raw[PREFIX_BYTES..], inner);
            return raw;
        }
        pub fn decode(a: std.mem.Allocator, raw: []const u8, expected: [32]u8, source: Source, config: core.pcs.PcsConfig, limits: Limits) !Owned {
            if (raw.len > limits.max_bytes) return error.ExecutionManifestResourceLimit;
            if (raw.len < HEADER_BYTES) return error.TruncatedExecutionManifest;
            if (!std.mem.eql(u8, raw[0..8], MAGIC) or std.mem.readInt(u32, raw[8..12], .little) != 1) return error.InvalidExecutionManifestVersion;
            if (!std.mem.eql(u8, &identity(raw), &expected)) return error.UntrustedExecutionManifest;
            const ext = try extension_wire.decodeExtension(raw[12..PREFIX_BYTES]);
            const inner = raw[PREFIX_BYTES..];
            // The caller-pinned outer identity has authenticated both sections. The
            // inner digest is only framing reuse, never proof-selected key authority.
            return .{ .base = try base.decodeWithContext(a, inner, base.identity(inner), source, config, limits, Context{ .extension = ext }), .extension = ext };
        }
    };
}
