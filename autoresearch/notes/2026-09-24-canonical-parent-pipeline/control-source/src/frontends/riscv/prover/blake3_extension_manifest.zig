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
        const geometry = @import("../recursion/air/compact_range_geometry.zig");
        const range_wire = @import("compact_range_codec.zig");
        const RANGE_BYTES = 32 + range_wire.ENCODED_BYTES;
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
            ranges: ?geometry.Plan = null,
            pub fn validate(self: @This(), shape: *const native) !void {
                try shape.validateBlake3ExecutionWithExternal(Profile.externalCount(&self.extension));
                try Profile.validateGeometry(&self.extension, shape.total_steps);
                if (self.ranges) |ranges| try (@import("compact_execution_contract.zig").Contract{ .native = shape, .ranges = ranges }).validate(Profile.externalCount(&self.extension));
            }
            pub fn mix(self: @This(), a: std.mem.Allocator, channel: anytype, config: core.pcs.PcsConfig, shape: *const native, pin: plans.Admission) !void {
                const logs = try @import("blake3_commitment_columns.zig").traceLogs(a, pin);
                if (self.ranges) |ranges| try (@import("compact_extension_contract.zig").ForProfile(Profile){ .native = shape, .extension = &self.extension, .ranges = ranges }).mix(channel, config, pin, logs) else try Profile.protocol.mix(channel, config, shape, &self.extension, pin, logs);
            }
        };
        pub fn encode(a: std.mem.Allocator, shape: *const native, ext: extension.Statement, pin: plans.Admission, config: core.pcs.PcsConfig, source: Source, limits: Limits) ![]u8 {
            return encodeMode(a, shape, ext, pin, config, source, limits, null);
        }
        pub fn encodeCompact(a: std.mem.Allocator, shape: *const native, ext: extension.Statement, pin: plans.Admission, config: core.pcs.PcsConfig, source: Source, limits: Limits, ranges: geometry.Plan) ![]u8 {
            return encodeMode(a, shape, ext, pin, config, source, limits, ranges);
        }
        fn encodeMode(a: std.mem.Allocator, shape: *const native, ext: extension.Statement, pin: plans.Admission, config: core.pcs.PcsConfig, source: Source, limits: Limits, ranges: ?geometry.Plan) ![]u8 {
            const inner = try base.encodeWithContext(a, shape, pin, config, source, limits, Context{ .extension = ext, .ranges = ranges });
            defer a.free(inner);
            const prefix = PREFIX_BYTES + @as(usize, if (ranges != null) RANGE_BYTES else 0);
            const size = try std.math.add(usize, prefix, inner.len);
            if (size > limits.max_bytes) return error.ExecutionManifestResourceLimit;
            const raw = try a.alloc(u8, size);
            errdefer a.free(raw);
            @memcpy(raw[0..8], MAGIC);
            std.mem.writeInt(u32, raw[8..12], if (ranges != null) 2 else 1, .little);
            var stream = std.io.fixedBufferStream(raw[12..PREFIX_BYTES]);
            try extension_wire.encodeExtension(stream.writer(), &ext);
            std.debug.assert(stream.pos == extension_wire.extension_encoded_size);
            if (ranges) |compact| {
                const id = try compact.identity();
                @memcpy(raw[PREFIX_BYTES..][0..32], &id);
                const encoded = try range_wire.encode(compact);
                @memcpy(raw[PREFIX_BYTES + 32 .. prefix], &encoded);
            }
            @memcpy(raw[prefix..], inner);
            return raw;
        }
        pub fn decode(a: std.mem.Allocator, raw: []const u8, expected: [32]u8, source: Source, config: core.pcs.PcsConfig, limits: Limits) !Owned {
            if (raw.len > limits.max_bytes) return error.ExecutionManifestResourceLimit;
            if (raw.len < HEADER_BYTES) return error.TruncatedExecutionManifest;
            const version = std.mem.readInt(u32, raw[8..12], .little);
            if (!std.mem.eql(u8, raw[0..8], MAGIC) or (version != 1 and version != 2)) return error.InvalidExecutionManifestVersion;
            if (!std.mem.eql(u8, &identity(raw), &expected)) return error.UntrustedExecutionManifest;
            const ext = try extension_wire.decodeExtension(raw[12..PREFIX_BYTES]);
            const prefix = PREFIX_BYTES + @as(usize, if (version == 2) RANGE_BYTES else 0);
            if (raw.len < prefix + base.HEADER_BYTES) return error.TruncatedExecutionManifest;
            const ranges: ?geometry.Plan = if (version == 2) try range_wire.decode(raw[PREFIX_BYTES + 32 .. prefix], raw[PREFIX_BYTES..][0..32].*) else null;
            const inner = raw[prefix..];
            // The caller-pinned outer identity has authenticated both sections. The
            // inner digest is only framing reuse, never proof-selected key authority.
            var decoded = try base.decodeWithContext(a, inner, base.identity(inner), source, config, limits, Context{ .extension = ext, .ranges = ranges });
            decoded.ranges = ranges;
            return .{ .base = decoded, .extension = ext };
        }
    };
}
