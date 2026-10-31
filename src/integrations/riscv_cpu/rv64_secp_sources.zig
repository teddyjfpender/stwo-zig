//! Concrete projective arithmetic/copy sources. This does not own CPU, global
//! BYTE, or RAM boundary closure. All lookup masses must join the outer roster.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const rv = @import("stwo_riscv_frontend").rv64_air;
pub const S = rv.crypto.secp256k1;
const L = S.layout;
const Storage = rv.crypto.main_storage;
const B = S.bridge;
const BL = B.layout;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
pub const Kind = S.program.Kind;
pub const Call = B.trace.Call;
pub const Format = B.equations.PacketFormat;
pub const Offsets = S.component.Offsets;
pub const FIXED = 2 * L.FIXED + BL.FIXED;
pub const MAIN = L.main(.product) + L.main(.linear) + BL.MAIN;
pub const INTERACTION = L.interaction(.product) + L.interaction(.linear) + BL.INTERACTION;
pub const Mass = struct { byte_queries: u64, wire_queries: u64, ram_queries: u64, call_queries: u64, product_identities: u64 };
pub const Geometry = struct {
    product_log: u32,
    linear_log: u32,
    bridge_log: u32,
    pub fn minimal(kind: Kind, calls: usize) !Geometry {
        const p = S.program.get(kind);
        return .{ .product_log = try L.logSize(.product, p, calls), .linear_log = try L.logSize(.linear, p, calls), .bridge_log = try B.trace.logSize(p, calls) };
    }
    pub fn validate(self: Geometry, kind: Kind, calls: usize, first_id: u32) !Mass {
        const p = S.program.get(kind);
        try B.trace.validateGeometry(p, calls, first_id, self.bridge_log);
        const bridge_bytes = try std.math.mul(u64, BL.RANGE_COUNT, @as(u64, 1) << @intCast(self.bridge_log));
        const mass = try L.admitRoster(&.{ .{ .kind = .product, .program = p, .calls = calls, .first_id = first_id, .log = self.product_log }, .{ .kind = .linear, .program = p, .calls = calls, .first_id = first_id, .log = self.linear_log } }, &.{bridge_bytes});
        const wires = try std.math.add(u64, mass.wires, try std.math.mul(u64, p.inputs + 3, @intCast(calls)));
        const ram = try std.math.mul(u64, 8 * @as(u64, p.inputs), @intCast(calls));
        if (wires >= core.fields.m31.Modulus or ram >= core.fields.m31.Modulus) return error.SecpLookupMassExceeded;
        return .{ .byte_queries = mass.bytes, .wire_queries = wires, .ram_queries = ram, .call_queries = @intCast(calls), .product_identities = try std.math.mul(u64, p.rows(true), @intCast(calls)) };
    }
    pub fn appendLogs(self: Geometry, out: []u32, at: *usize, tree: u2) !void {
        const counts = try countsFor(tree);
        if (at.* > out.len or out.len - at.* < counts[0] + counts[1] + counts[2]) return error.InvalidSecpSourceShape;
        for (counts, [_]u32{ self.product_log, self.linear_log, self.bridge_log }) |count, log| {
            @memset(out[at.*..][0..count], log);
            at.* += count;
        }
    }
};
pub const MainBuffers = struct {
    product: []M,
    linear: []M,
    bridge: []M,
    pub fn slices(self: MainBuffers, geometry: Geometry) [3]Storage.Slice {
        return .{ .{ .values = self.product, .cells = L.main(.product) * (@as(usize, 1) << @intCast(geometry.product_log)) }, .{ .values = self.linear, .cells = L.main(.linear) * (@as(usize, 1) << @intCast(geometry.linear_log)) }, .{ .values = self.bridge, .cells = BL.MAIN * (@as(usize, 1) << @intCast(geometry.bridge_log)) } };
    }
    pub fn validate(self: MainBuffers, geometry: Geometry, kind: Kind, calls: usize, first_id: u32) !void {
        _ = try geometry.validate(kind, calls, first_id);
        try Storage.validate(&self.slices(geometry));
    }
};
pub const Materials = struct {
    allocator: std.mem.Allocator,
    kind: Kind,
    geometry: Geometry,
    product_fixed: []M,
    linear_fixed: []M,
    bridge_fixed: []M,
    pub fn init(a: std.mem.Allocator, kind: Kind, geometry: Geometry) !Materials {
        _ = try geometry.validate(kind, 0, 1);
        const program = S.program.get(kind);
        const product = try S.trace.fixedColumns(a, .product, program, geometry.product_log);
        errdefer a.free(product);
        const linear = try S.trace.fixedColumns(a, .linear, program, geometry.linear_log);
        errdefer a.free(linear);
        return .{ .allocator = a, .kind = kind, .geometry = geometry, .product_fixed = product, .linear_fixed = linear, .bridge_fixed = try B.trace.fixedColumnsForLog(a, program, geometry.bridge_log) };
    }
    pub fn deinit(self: *Materials) void {
        self.allocator.free(self.bridge_fixed);
        self.allocator.free(self.linear_fixed);
        self.allocator.free(self.product_fixed);
        self.* = undefined;
    }
    pub fn appendFixed(self: *const Materials, out: []Column, at: *usize) !void {
        _ = try self.geometry.validate(self.kind, 0, 1);
        try storageShape(self.product_fixed.len, L.FIXED, self.geometry.product_log);
        try storageShape(self.linear_fixed.len, L.FIXED, self.geometry.linear_log);
        try storageShape(self.bridge_fixed.len, BL.FIXED, self.geometry.bridge_log);
        try capacity(out.len, at.*, FIXED);
        try append(out, at, self.product_fixed, self.geometry.product_log);
        try append(out, at, self.linear_fixed, self.geometry.linear_log);
        try append(out, at, self.bridge_fixed, self.geometry.bridge_log);
    }
};
pub const Challenges = struct {
    arithmetic: S.equations.Challenges,
    call: B.equations.CallChallenges,
    ram: rv.relations.Challenges,
    /// Draw ONCE for both kinds, after every fixed/main root is sealed. BYTE and
    /// RAM are the outer transaction's shared families, never drawn again here.
    pub fn draw(channel: anytype, bytes: Q, ram: rv.relations.Challenges) Challenges {
        return .{ .arithmetic = .{ .polynomial = channel.drawSecureFelt(), .bytes = bytes, .wire = S.equations.Wire.draw(channel) }, .call = B.equations.CallChallenges.draw(channel), .ram = ram };
    }
    pub fn bridge(self: Challenges) B.equations.Challenges {
        return .{ .wire = self.arithmetic.wire, .bytes = self.arithmetic.bytes, .call = self.call, .ram = self.ram };
    }
};
pub const Claims = struct {
    product: Q,
    linear: Q,
    bridge: Q,
    pub fn validateCanonical(self: Claims) !void {
        for ([_]Q{ self.product, self.linear, self.bridge }) |v| for (v.toM31Array()) |limb| if (limb.v >= core.fields.m31.Modulus) return error.InvalidSecpSourceClaim;
    }
    pub fn sum(self: Claims) Q {
        return self.product.add(self.linear).add(self.bridge);
    }
};
pub const Trace = struct {
    kind: Kind,
    geometry: Geometry,
    format: Format,
    first_id: u32,
    calls: u32,
    product: S.trace.Trace,
    linear: S.trace.Trace,
    bridge: B.trace.Trace,
    byte_counts: [256]u64,
    claims: ?Claims = null,
    pub fn init(a: std.mem.Allocator, kind: Kind, calls: []const Call, first_id: u32, format: Format, geometry: Geometry) !Trace {
        return create(a, a, kind, calls, first_id, format, geometry, null, null);
    }
    /// Materials must outlive this trace. Fixed source slices are borrowed; no
    /// fixed matrices or roots are reconstructed during request materialization.
    pub fn initPrepared(a: std.mem.Allocator, materials: *const Materials, calls: []const Call, first_id: u32, format: Format) !Trace {
        return create(a, a, materials.kind, calls, first_id, format, materials.geometry, materials, null);
    }
    pub fn initWithMainAllocator(a: std.mem.Allocator, main_allocator: std.mem.Allocator, kind: Kind, calls: []const Call, first_id: u32, format: Format, geometry: Geometry) !Trace {
        return create(a, main_allocator, kind, calls, first_id, format, geometry, null, null);
    }
    pub fn initPreparedWithMainAllocator(a: std.mem.Allocator, main_allocator: std.mem.Allocator, materials: *const Materials, calls: []const Call, first_id: u32, format: Format) !Trace {
        return create(a, main_allocator, materials.kind, calls, first_id, format, materials.geometry, materials, null);
    }
    pub fn initPreparedWithMainBuffers(a: std.mem.Allocator, materials: *const Materials, calls: []const Call, first_id: u32, format: Format, main: MainBuffers) !Trace {
        return create(a, a, materials.kind, calls, first_id, format, materials.geometry, materials, main);
    }
    pub fn initWithMainBuffers(a: std.mem.Allocator, kind: Kind, calls: []const Call, first_id: u32, format: Format, geometry: Geometry, main: MainBuffers) !Trace {
        return create(a, a, kind, calls, first_id, format, geometry, null, main);
    }
    fn create(a: std.mem.Allocator, main_allocator: std.mem.Allocator, kind: Kind, calls: []const Call, first_id: u32, format: Format, geometry: Geometry, materials: ?*const Materials, main: ?MainBuffers) !Trace {
        _ = try geometry.validate(kind, calls.len, first_id);
        if (main) |m| {
            try m.validate(geometry, kind, calls.len, first_id);
            const slices = m.slices(geometry);
            try Storage.exclude(&slices, std.mem.sliceAsBytes(calls));
            if (materials) |fixed| {
                try Storage.exclude(&slices, std.mem.sliceAsBytes(fixed.product_fixed));
                try Storage.exclude(&slices, std.mem.sliceAsBytes(fixed.linear_fixed));
                try Storage.exclude(&slices, std.mem.sliceAsBytes(fixed.bridge_fixed));
            }
        }
        if (materials) |m| {
            if (m.kind != kind or !std.meta.eql(m.geometry, geometry)) return error.InvalidSecpSourceShape;
            try storageShape(m.product_fixed.len, L.FIXED, geometry.product_log);
            try storageShape(m.linear_fixed.len, L.FIXED, geometry.linear_log);
            try storageShape(m.bridge_fixed.len, BL.FIXED, geometry.bridge_log);
        }
        const program = S.program.get(kind);
        var bridge = if (main) |m| try B.trace.Trace.initWithMainBuffer(a, program, calls, first_id, geometry.bridge_log, format, if (materials) |fixed| fixed.bridge_fixed else null, m.bridge) else if (materials) |m| try B.trace.Trace.initWithPreparedFixedAndMainAllocator(a, main_allocator, program, calls, first_id, geometry.bridge_log, format, m.bridge_fixed) else try B.trace.Trace.initWithLogAndFormatAndMainAllocator(a, main_allocator, program, calls, first_id, geometry.bridge_log, format);
        errdefer bridge.deinit();
        const fixed: ?S.batch.FixedColumns = if (materials) |m| .{ .product = m.product_fixed, .linear = m.linear_fixed } else null;
        var batch = if (main) |m| try S.batch.Batch.initFromPacketsWithMainBuffers(a, program, calls, first_id, format, geometry.product_log, geometry.linear_log, fixed, .{ .product = m.product, .linear = m.linear }) else try S.batch.Batch.initFromPacketsWithMainAllocator(a, main_allocator, program, calls, first_id, format, geometry.product_log, geometry.linear_log, fixed);
        errdefer batch.deinit();
        var bytes: [256]u64 = undefined;
        for (&bytes, batch.product.byte_counts, batch.linear.byte_counts, bridge.byte_counts) |*v, p, l, b| v.* = try std.math.add(u64, try std.math.add(u64, p, l), b);
        return .{ .kind = kind, .geometry = geometry, .format = format, .first_id = first_id, .calls = @intCast(calls.len), .product = batch.product, .linear = batch.linear, .bridge = bridge, .byte_counts = bytes };
    }
    pub fn deinit(self: *Trace) void {
        self.bridge.deinit();
        self.linear.deinit();
        self.product.deinit();
        self.* = undefined;
    }
    pub fn validateMetadata(self: *const Trace) !void {
        _ = try self.geometry.validate(self.kind, self.calls, self.first_id);
        if (self.product.kind != .product or self.linear.kind != .linear or self.product.program.kind != self.kind or self.linear.program.kind != self.kind or self.bridge.program.kind != self.kind or self.product.log_size != self.geometry.product_log or self.linear.log_size != self.geometry.linear_log or self.bridge.log_size != self.geometry.bridge_log or self.product.calls != self.calls or self.linear.calls != self.calls or self.bridge.calls != self.calls or self.product.first_id != self.first_id or self.linear.first_id != self.first_id or self.bridge.first_id != self.first_id or self.bridge.packet_format != self.format) return error.InvalidSecpSourceShape;
        try storageShape(self.product.fixed.len, L.FIXED, self.geometry.product_log);
        try storageShape(self.linear.fixed.len, L.FIXED, self.geometry.linear_log);
        try storageShape(self.bridge.fixed.len, BL.FIXED, self.geometry.bridge_log);
        try self.product.validateMetadata();
        try self.linear.validateMetadata();
        try self.bridge.validateMetadata();
    }
    pub fn validateMain(self: *const Trace) !void {
        try self.validateMetadata();
        try storageShape(self.product.main.len, L.main(.product), self.geometry.product_log);
        try storageShape(self.linear.main.len, L.main(.linear), self.geometry.linear_log);
        try storageShape(self.bridge.main.len, BL.MAIN, self.geometry.bridge_log);
    }
    pub fn appendMain(self: *const Trace, out: []Column, at: *usize) !void {
        if (self.product.main.len == 0 or self.linear.main.len == 0 or self.bridge.main.len == 0) return error.InvalidSecpSourcePhase;
        try self.validateMain();
        try capacity(out.len, at.*, MAIN);
        try append(out, at, self.product.main, self.geometry.product_log);
        try append(out, at, self.linear.main, self.geometry.linear_log);
        try append(out, at, self.bridge.main, self.geometry.bridge_log);
    }
    pub fn appendInteraction(self: *const Trace, out: []Column, at: *usize) !void {
        if (self.claims == null) return error.InvalidSecpSourcePhase;
        try storageShape(self.product.interaction.len, L.interaction(.product), self.geometry.product_log);
        try storageShape(self.linear.interaction.len, L.interaction(.linear), self.geometry.linear_log);
        try storageShape(self.bridge.interaction.len, BL.INTERACTION, self.geometry.bridge_log);
        try capacity(out.len, at.*, INTERACTION);
        try append(out, at, self.product.interaction, self.geometry.product_log);
        try append(out, at, self.linear.interaction, self.geometry.linear_log);
        try append(out, at, self.bridge.interaction, self.geometry.bridge_log);
    }
    pub fn generate(self: *Trace, ch: Challenges) !Claims {
        if (self.claims != null or self.product.interaction.len != 0 or self.linear.interaction.len != 0 or self.bridge.interaction.len != 0) return error.InvalidSecpSourcePhase;
        try self.validateMetadata();
        errdefer {
            self.product.allocator.free(self.product.interaction);
            self.product.interaction = &.{};
            self.linear.allocator.free(self.linear.interaction);
            self.linear.interaction = &.{};
            self.bridge.allocator.free(self.bridge.interaction);
            self.bridge.interaction = &.{};
        }
        const claims = Claims{ .product = try self.product.generateInteraction(ch.arithmetic), .linear = try self.linear.generateInteraction(ch.arithmetic), .bridge = try self.bridge.generateInteraction(ch.bridge()) };
        self.claims = claims;
        if (self.product.main.len == 0 and self.linear.main.len == 0 and self.bridge.main.len == 0) try self.releaseMetadata();
        return claims;
    }
    pub fn takeMain(self: *Trace) ![3][]M {
        if (!self.product.owns_main or !self.linear.owns_main or !self.bridge.owns_main) return error.BorrowedCryptoMain;
        if (self.product.main.len == 0 or self.linear.main.len == 0 or self.bridge.main.len == 0) return error.InvalidSecpSourcePhase;
        try self.validateMain();
        const data = [3][]M{ self.product.main, self.linear.main, self.bridge.main };
        self.product.main = &.{};
        self.linear.main = &.{};
        self.bridge.main = &.{};
        if (self.claims != null) try self.releaseMetadata();
        return data;
    }
    pub fn releaseMain(self: *Trace) !void {
        try self.validateMain();
        try self.product.releaseMain();
        try self.linear.releaseMain();
        try self.bridge.releaseMain();
        if (self.claims != null) try self.releaseMetadata();
    }
    pub fn releaseMetadata(self: *Trace) !void {
        if (self.claims == null or self.product.main.len != 0 or self.linear.main.len != 0 or self.bridge.main.len != 0) return error.InvalidSecpSourcePhase;
        self.product.allocator.free(self.product.lookup_bytes);
        self.product.lookup_bytes = &.{};
        self.linear.allocator.free(self.linear.lookup_bytes);
        self.linear.lookup_bytes = &.{};
        self.bridge.allocator.free(self.bridge.metadata);
        self.bridge.metadata = &.{};
    }
};
pub const Components = struct {
    product: S.component.Component,
    linear: S.component.Component,
    bridge: B.component.Component,
    pub fn init(kind: Kind, geometry: Geometry, calls: u32, first_id: u32, format: Format, offset: Offsets, ch: Challenges, claims: Claims) !Components {
        _ = try geometry.validate(kind, calls, first_id);
        try claims.validateCanonical();
        const program = S.program.get(kind);
        return .{
            .product = .{ .kind = .product, .program = program, .log_size = geometry.product_log, .public = .{ .calls = calls, .first_id = first_id }, .offsets = offset, .challenges = ch.arithmetic, .claim = claims.product },
            .linear = .{ .kind = .linear, .program = program, .log_size = geometry.linear_log, .public = .{ .calls = calls, .first_id = first_id }, .offsets = .{ .fixed = offset.fixed + L.FIXED, .main = offset.main + L.main(.product), .interaction = offset.interaction + L.interaction(.product) }, .challenges = ch.arithmetic, .claim = claims.linear },
            .bridge = .{ .program = program, .log_size = geometry.bridge_log, .calls = calls, .first_call_id = first_id, .packet_format = format, .offsets = .{ .fixed = offset.fixed + 2 * L.FIXED, .main = offset.main + L.main(.product) + L.main(.linear), .interaction = offset.interaction + L.interaction(.product) + L.interaction(.linear) }, .challenges = ch.bridge(), .claim = claims.bridge },
        };
    }
    pub fn appendProver(self: *const Components, out: []engine.air.component_prover.ComponentProver, at: *usize) !void {
        try capacity(out.len, at.*, 3);
        out[at.*] = self.product.asProverComponent();
        out[at.* + 1] = self.linear.asProverComponent();
        out[at.* + 2] = self.bridge.asProverComponent();
        at.* += 3;
    }
    pub fn appendVerifier(self: *const Components, out: []core.air.components.Component, at: *usize) !void {
        try capacity(out.len, at.*, 3);
        out[at.*] = self.product.asVerifierComponent();
        out[at.* + 1] = self.linear.asVerifierComponent();
        out[at.* + 2] = self.bridge.asVerifierComponent();
        at.* += 3;
    }
};
fn capacity(len: usize, at: usize, count: usize) !void {
    if (at > len or len - at < count) return error.InvalidSecpSourceShape;
}
fn countsFor(tree: u2) ![3]usize {
    return switch (tree) {
        0 => .{ L.FIXED, L.FIXED, BL.FIXED },
        1 => .{ L.main(.product), L.main(.linear), BL.MAIN },
        2 => .{ L.interaction(.product), L.interaction(.linear), BL.INTERACTION },
        else => error.InvalidSecpSourceTree,
    };
}
fn append(out: []Column, at: *usize, storage: []const M, log: u32) !void {
    const n = @as(usize, 1) << @intCast(log);
    if (storage.len % n != 0) return error.InvalidSecpSourceShape;
    const count = storage.len / n;
    try capacity(out.len, at.*, count);
    for (0..count) |c| {
        out[at.*] = .{ .log_size = log, .values = storage[c * n ..][0..n] };
        at.* += 1;
    }
}

fn storageShape(len: usize, columns: usize, log: u32) !void {
    if (log < 5 or log > 22 or len != columns * (@as(usize, 1) << @intCast(log))) return error.InvalidSecpSourceShape;
}
