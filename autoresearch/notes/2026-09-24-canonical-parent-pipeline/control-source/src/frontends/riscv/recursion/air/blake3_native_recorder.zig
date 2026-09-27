//! Owning event sink for the native transcript encoders; no alternate hashing.
const std = @import("std");
const core = @import("stwo_core");
const t = @import("blake3_transcript_witness.zig");
const Q = core.fields.qm31.QM31;
pub const CLAIM_CIRCUIT: u32 = 4_100_000;
pub const Payload = struct { source: t.Caller, values: []const Q };
pub const Recorder = struct {
    a: std.mem.Allocator,
    native: core.channel.blake3.Channel = .{},
    operations: std.ArrayList(t.Operation) = .empty,
    payloads: std.ArrayList(Payload) = .empty,
    failure: ?anyerror = null,
    private_felts: bool = false,
    next_payload: u32 = 0,
    root_count: usize = 0,
    relation_count: usize = 0,
    universal_relations: bool = false,
    nonce_pending: ?u64 = null,
    pub const nonce_source = t.Caller{ .circuit = 4_100_001, .first_wire = 0 };
    pub fn check(self: *const Recorder) !void {
        if (self.failure) |err| return err;
    }
    fn append(self: *Recorder, operation: t.Operation) void {
        if (self.failure != null) return;
        self.operations.append(self.a, operation) catch |err| {
            self.failure = err;
        };
    }
    pub fn mixU32s(self: *Recorder, values: []const u32) void {
        if (self.failure != null) return;
        const owned = self.a.dupe(u32, values) catch |err| {
            self.failure = err;
            return;
        };
        self.append(.{ .words = owned });
        self.native.mixU32s(values);
    }
    pub fn mixFelts(self: *Recorder, values: []const Q) void {
        if (self.failure != null) return;
        const owned = self.a.dupe(Q, values) catch |err| {
            self.failure = err;
            return;
        };
        if (self.private_felts) {
            const source = t.Caller{ .circuit = CLAIM_CIRCUIT, .first_wire = self.next_payload };
            const words = std.math.mul(usize, values.len, 4) catch |err| {
                self.failure = err;
                return;
            };
            const end = std.math.add(usize, self.next_payload, words) catch |err| {
                self.failure = err;
                return;
            };
            if (end >= core.fields.m31.Modulus) {
                self.failure = error.InvalidNativeBlake3Transcript;
                return;
            }
            self.next_payload = @intCast(end);
            self.payloads.append(self.a, .{ .source = source, .values = owned }) catch |err| {
                self.failure = err;
                return;
            };
            self.append(.{ .routed_felts = .{ .source = source, .values = owned } });
        } else self.append(.{ .felts = owned });
        self.native.mixFelts(values);
    }
    pub fn mixU64(self: *Recorder, value: u64) void {
        if (self.failure != null) return;
        if (self.nonce_pending) |expected| {
            if (value != expected) {
                self.failure = error.InvalidNativeBlake3Transcript;
                return;
            }
            self.append(.{ .routed_integer = .{ .value = value, .source = nonce_source } });
            self.nonce_pending = null;
        } else self.append(.{ .integer = value });
        self.native.mixU64(value);
    }
    pub fn mixRoot(self: *Recorder, value: [32]u8) void {
        if (self.failure != null) return;
        const source = @import("blake3_root_sources.zig").caller(self.root_count) catch |err| {
            self.failure = err;
            return;
        };
        self.root_count += 1;
        self.append(.{ .routed_root = .{ .value = value, .source = source } });
        self.native.mixRoot(value);
    }
    pub fn verifyPowNonce(self: *Recorder, bits: u32, nonce: u64) bool {
        if (self.failure != null) return false;
        if (self.nonce_pending != null) {
            self.failure = error.InvalidNativeBlake3Transcript;
            return false;
        }
        self.nonce_pending = nonce;
        self.append(.{ .pow = .{ .bits = bits, .nonce = nonce, .nonce_source = nonce_source } });
        return self.native.verifyPowNonce(bits, nonce);
    }
    pub fn drawSecureFelts(self: *Recorder, a: std.mem.Allocator, count: usize) ![]Q {
        try self.check();
        if (count % 2 != 0 or self.nonce_pending != null) return error.InvalidNativeBlake3Transcript;
        const values = try self.native.drawSecureFelts(a, count);
        errdefer a.free(values);
        var i: usize = 0;
        while (i < count) : (i += 2) {
            const coordinates = values[i].toM31Array() ++ values[i + 1].toM31Array();
            self.append(.{ .secure = .{ .output = if (self.universal_relations) .{ .universal = self.relation_count } else .{ .riscv_relation = self.relation_count }, .attempts = 0, .consumption = .two, .values = coordinates } });
            self.relation_count += 1;
        }
        try self.check();
        return values;
    }
};
