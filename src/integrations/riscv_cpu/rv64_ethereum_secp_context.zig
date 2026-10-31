//! Two concrete independently sized secp families. This owns no CPU or global
//! BYTE/state closure; an explicit outer transaction supplies both challenges.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const frontend = @import("stwo_riscv_frontend");
const Profile = frontend.rv64.execution_profile.Profile;
const rv = frontend.rv64_air;
pub const Source = @import("rv64_secp_sources.zig");
pub const MainBuffers = [2]?Source.MainBuffers;
const Storage = rv.crypto.main_storage;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
pub const Roster = enum(u32) { none = 0, present = 1 };
pub const Group = struct {
    roster: Roster = .none,
    calls: u32 = 0,
    first_id: u32 = 1,
    geometry: Source.Geometry = .{ .product_log = 5, .linear_log = 5, .bridge_log = 5 },
};
pub const Metadata = struct {
    add: Group = .{},
    double: Group = .{},
    pub fn groups(self: Metadata) [2]Group {
        return .{ self.add, self.double };
    }
    pub fn counts(self: Metadata) [2]u32 {
        return .{ self.add.calls, self.double.calls };
    }
    pub fn firstIds(self: Metadata) [2]u32 {
        return .{ self.add.first_id, self.double.first_id };
    }
    pub fn validate(self: Metadata, profile: Profile, steps: u32) !Source.Mass {
        if (profile == .keccak_service_v1) {
            if (!std.meta.eql(self, Metadata{})) return error.InvalidRv64SecpMetadata;
            return .{ .byte_queries = 0, .wire_queries = 0, .ram_queries = 0, .call_queries = 0, .product_identities = 0 };
        }
        if (profile != .ethereum_services_v1 and profile != .ethereum_services_v2) return error.InvalidRv64SecpMetadata;
        if (@as(u64, self.add.calls) + self.double.calls > steps) return error.InvalidRv64SecpMetadata;
        var mass = Source.Mass{ .byte_queries = 0, .wire_queries = 0, .ram_queries = 0, .call_queries = 0, .product_identities = 0 };
        for (self.groups(), 0..) |g, k| {
            if (g.roster == .none) {
                if (g.calls != 0 or !std.meta.eql(g.geometry, (Group{}).geometry) or g.first_id == 0 or g.first_id >= core.fields.m31.Modulus) return error.InvalidRv64SecpMetadata;
            } else {
                const next = try g.geometry.validate(if (k == 0) .add else .double, g.calls, g.first_id);
                mass.byte_queries = try std.math.add(u64, mass.byte_queries, next.byte_queries);
                mass.wire_queries = try std.math.add(u64, mass.wire_queries, next.wire_queries);
                mass.ram_queries = try std.math.add(u64, mass.ram_queries, next.ram_queries);
                mass.call_queries = try std.math.add(u64, mass.call_queries, next.call_queries);
                mass.product_identities = try std.math.add(u64, mass.product_identities, next.product_identities);
            }
        }
        if (mass.byte_queries >= core.fields.m31.Modulus or mass.wire_queries >= core.fields.m31.Modulus or mass.ram_queries >= core.fields.m31.Modulus or mass.call_queries >= core.fields.m31.Modulus) return error.SecpLookupMassExceeded;
        return mass;
    }
    pub fn mix(self: Metadata, channel: *rv.protocol.Channel, profile: Profile) void {
        if (profile == .keccak_service_v1) return;
        channel.mixU32s(&.{ 0x45544853, 1, @intFromEnum(profile) });
        for (self.groups()) |g| channel.mixU32s(&.{ @intFromEnum(g.roster), g.calls, g.first_id, g.geometry.product_log, g.geometry.linear_log, g.geometry.bridge_log });
    }
};
pub const Claims = struct {
    product: Q = Q.zero(),
    linear: Q = Q.zero(),
    bridge: Q = Q.zero(),
    pub fn sum(self: Claims) Q {
        return self.product.add(self.linear).add(self.bridge);
    }
    pub fn source(self: Claims) Source.Claims {
        return .{ .product = self.product, .linear = self.linear, .bridge = self.bridge };
    }
};
pub fn validateClaims(meta: Metadata, profile: Profile, header: Q, claims: [2]Claims) !void {
    for (header.toM31Array()) |part| if (part.v >= core.fields.m31.Modulus) return error.InvalidSecpSourceClaim;
    for (meta.groups(), claims) |g, c| {
        try c.source().validateCanonical();
        if (g.roster == .none and (!c.product.isZero() or !c.linear.isZero() or !c.bridge.isZero())) return error.Rv64ServiceOmittedClaim;
    }
    if ((profile == .keccak_service_v1 or (meta.add.roster == .none and meta.double.roster == .none)) and !header.isZero()) return error.Rv64ServiceOmittedClaim;
}
pub const Materials = struct {
    groups: [2]?Source.Materials = .{ null, null },
    pub fn init(a: std.mem.Allocator, meta: Metadata) !Materials {
        var result = Materials{};
        errdefer result.deinit();
        for (meta.groups(), 0..) |g, k| if (g.roster == .present) {
            result.groups[k] = try Source.Materials.init(a, if (k == 0) .add else .double, g.geometry);
        };
        return result;
    }
    pub fn deinit(self: *Materials) void {
        for (&self.groups) |*g| if (g.*) |*source| {
            source.deinit();
        };
        self.* = undefined;
    }
    pub fn count(self: *const Materials) usize {
        var n: usize = 0;
        for (self.groups) |g| n += @intFromBool(g != null);
        return n;
    }
    pub fn validate(self: *const Materials, meta: Metadata) !void {
        for (self.groups, meta.groups(), 0..) |g, expected, k| {
            if ((g != null) != (expected.roster == .present)) return error.InvalidSecpSourceShape;
            if (g) |source| if (source.kind != (if (k == 0) Source.Kind.add else Source.Kind.double) or !std.meta.eql(source.geometry, expected.geometry)) return error.InvalidSecpSourceShape;
        }
    }
    pub fn appendFixed(self: *const Materials, out: []Column, at: *usize) !void {
        for (&self.groups) |*g| if (g.*) |*source| {
            try source.appendFixed(out, at);
        };
    }
    pub fn appendLogs(self: *const Materials, out: []u32, at: *usize, tree: u2) !void {
        for (self.groups) |g| if (g) |source| {
            try source.geometry.appendLogs(out, at, tree);
        };
    }
};
pub const Trace = struct {
    groups: [2]?Source.Trace = .{ null, null },
    byte_counts: [256]u64 = @splat(0),
    pub fn initPrepared(a: std.mem.Allocator, material: *const Materials, calls: [2][]const Source.Call, meta: Metadata, profile: Profile) !Trace {
        return create(a, material, calls, meta, profile, null);
    }
    pub fn initPreparedWithMainBuffers(a: std.mem.Allocator, material: *const Materials, calls: [2][]const Source.Call, meta: Metadata, profile: Profile, main: MainBuffers) !Trace {
        return create(a, material, calls, meta, profile, main);
    }
    fn create(a: std.mem.Allocator, material: *const Materials, calls: [2][]const Source.Call, meta: Metadata, profile: Profile, main: ?MainBuffers) !Trace {
        if (main) |buffers| {
            try material.validate(meta);
            var all: [6]Storage.Slice = undefined;
            var at: usize = 0;
            for (material.groups, meta.groups(), calls, buffers, 0..) |source, g, list, buffer, k| {
                if ((source != null) != (buffer != null) or list.len != g.calls) return error.InvalidCryptoMainBuffers;
                if (buffer) |m| {
                    try m.validate(g.geometry, if (k == 0) .add else .double, list.len, g.first_id);
                    const slices = m.slices(g.geometry);
                    @memcpy(all[at..][0..3], &slices);
                    at += 3;
                }
            }
            try Storage.validate(all[0..at]);
            for (calls) |list| try Storage.exclude(all[0..at], std.mem.sliceAsBytes(list));
            for (material.groups) |source| if (source) |fixed| {
                var fixed_columns: [Source.FIXED]Column = undefined;
                var header_at: usize = 0;
                try fixed.appendFixed(&fixed_columns, &header_at);
                try Storage.exclude(all[0..at], std.mem.sliceAsBytes(fixed.product_fixed));
                try Storage.exclude(all[0..at], std.mem.sliceAsBytes(fixed.linear_fixed));
                try Storage.exclude(all[0..at], std.mem.sliceAsBytes(fixed.bridge_fixed));
            };
        }
        var result = Trace{};
        errdefer result.deinit();
        const format: Source.Format = if (profile == .ethereum_services_v1) .big_endian_bytes_v1 else .little_endian_words_v2;
        for (&material.groups, calls, meta.groups(), 0..) |*m, list, g, k| {
            if (list.len != g.calls) return error.InvalidRv64SecpMetadata;
            if (m.*) |*source| {
                result.groups[k] = if (main) |buffers| try Source.Trace.initPreparedWithMainBuffers(a, source, list, g.first_id, format, buffers[k].?) else try Source.Trace.initPrepared(a, source, list, g.first_id, format);
                for (&result.byte_counts, result.groups[k].?.byte_counts) |*sum, count| sum.* = try std.math.add(u64, sum.*, count);
            } else if (list.len != 0) return error.InvalidRv64SecpMetadata;
        }
        return result;
    }
    pub fn deinit(self: *Trace) void {
        for (&self.groups) |*g| if (g.*) |*source| {
            source.deinit();
        };
        self.* = undefined;
    }
    pub fn appendMain(self: *const Trace, out: []Column, at: *usize) !void {
        for (&self.groups) |*g| if (g.*) |*source| {
            try source.appendMain(out, at);
        };
    }
    pub fn releaseMain(self: *Trace) !void {
        for (&self.groups) |*g| if (g.*) |*source| {
            try source.validateMain();
        };
        for (&self.groups) |*g| if (g.*) |*source| {
            try source.releaseMain();
        };
    }
    pub fn appendInteraction(self: *const Trace, out: []Column, at: *usize) !void {
        for (&self.groups) |*g| if (g.*) |*source| {
            try source.appendInteraction(out, at);
        };
    }
    pub fn generate(self: *Trace, ch: Source.Challenges) ![2]Claims {
        var result: [2]Claims = .{ .{}, .{} };
        var generated: [2]bool = .{ false, false };
        errdefer for (&self.groups, generated) |*g, done| if (done) {
            const source = &g.*.?;
            source.product.allocator.free(source.product.interaction);
            source.product.interaction = &.{};
            source.linear.allocator.free(source.linear.interaction);
            source.linear.interaction = &.{};
            source.bridge.allocator.free(source.bridge.interaction);
            source.bridge.interaction = &.{};
            source.claims = null;
        };
        for (&self.groups, 0..) |*g, k| if (g.*) |*source| {
            const c = try source.generate(ch);
            result[k] = .{ .product = c.product, .linear = c.linear, .bridge = c.bridge };
            generated[k] = true;
        };
        return result;
    }
};
pub fn headers(a: std.mem.Allocator, calls: [2][]const Source.Call) ![]rv.crypto.secp256k1.cpu_bus.Call {
    const result = try a.alloc(rv.crypto.secp256k1.cpu_bus.Call, try std.math.add(usize, calls[0].len, calls[1].len));
    errdefer a.free(result);
    var at: [2]usize = .{ 0, 0 };
    for (result) |*header| {
        const k: usize = if (at[0] < calls[0].len and (at[1] == calls[1].len or calls[0][at[0]].clock < calls[1][at[1]].clock)) 0 else 1;
        const call = calls[k][at[k]];
        at[k] += 1;
        header.* = .{ .kind = if (k == 0) .add else .double, .call_id = call.call_id, .clock = call.clock, .pointer = call.pointer };
    }
    return result;
}
