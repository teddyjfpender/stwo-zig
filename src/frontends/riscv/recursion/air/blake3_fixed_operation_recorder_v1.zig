//! Fixed routing sink shared by original parent/native operation grammars.
//! Length-only public payload placeholders are consumed ONLY by trusted fixed
//! emitters. No channel/hash execution, nonce, claim or challenge is produced.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Schema = @import("blake3_pcs_operation_schema_v1.zig");
const t = @import("blake3_transcript_witness.zig");
pub const Limits = struct { max_operations: usize = 1 << 16, max_routed_words: usize = 1 << 20 };
pub const Recorder = struct {
    a: std.mem.Allocator,
    limits: Limits,
    operations: std.ArrayList(t.Operation) = .empty,
    routed_words: usize = 0,
    failure: ?anyerror = null,
    skipped_roots: usize = 0,
    pub fn append(self: *Recorder, operation: t.Operation) void {
        if (self.failure != null) return;
        if (self.operations.items.len >= self.limits.max_operations) {
            self.failure = error.RecursiveParentFixedTranscriptResourceLimit;
            return;
        }
        self.operations.append(self.a, operation) catch |failure| {
            self.failure = failure;
        };
    }
    fn admitWords(self: *Recorder, count: usize) !void {
        if (self.failure) |failure| return failure;
        const next = try std.math.add(usize, self.routed_words, count);
        if (next > self.limits.max_routed_words) return error.RecursiveParentFixedTranscriptResourceLimit;
        self.routed_words = next;
    }
    pub fn mixPublicRoot(self: *Recorder, source: t.Caller, _: [32]u8) void {
        self.admitWords(8) catch |failure| {
            self.failure = failure;
            return;
        };
        self.append(.{ .routed_root = .{ .value = @splat(0), .source = source } });
    }
    pub fn mixPublicInteger(self: *Recorder, source: t.Caller, _: u64) void {
        self.admitWords(2) catch |failure| {
            self.failure = failure;
            return;
        };
        self.append(.{ .routed_integer = .{ .value = 0, .source = source } });
    }
    pub fn mixPublicWords(self: *Recorder, source: t.Caller, values: []const u32) void {
        self.routedWords(source, values.len) catch |failure| {
            self.failure = failure;
        };
    }
    pub fn routedWords(self: *Recorder, source: t.Caller, count: usize) !void {
        try self.admitWords(count);
        const lengths_only = try self.a.alloc(u32, count);
        @memset(lengths_only, 0);
        self.append(.{ .routed_words = .{ .values = lengths_only, .source = source } });
    }
    pub fn mixPublicFelts(self: *Recorder, source: t.Caller, values: []const Q) void {
        self.routedFelts(source, values.len) catch |failure| {
            self.failure = failure;
        };
    }
    pub fn routedFelts(self: *Recorder, source: t.Caller, count: usize) !void {
        try self.admitWords(try std.math.mul(usize, count, 4));
        const lengths_only = try self.a.alloc(Q, count);
        @memset(lengths_only, Q.zero());
        self.append(.{ .routed_felts = .{ .values = lengths_only, .source = source } });
    }
    /// Only independently specified CONSTANT protocol frames use these methods.
    /// Changing public fields must pass the public-routing methods above.
    pub fn mixU32s(self: *Recorder, values: []const u32) void {
        if (self.failure != null) return;
        const constants = self.a.dupe(u32, values) catch |failure| {
            self.failure = failure;
            return;
        };
        self.append(.{ .words = constants });
    }
    pub fn mixFelts(self: *Recorder, values: []const Q) void {
        if (self.failure != null) return;
        const constants = self.a.dupe(Q, values) catch |failure| {
            self.failure = failure;
            return;
        };
        self.append(.{ .felts = constants });
    }
    pub fn mixRoot(self: *Recorder, value: [32]u8) void {
        self.append(.{ .root = value });
    }
    pub fn mixU64(self: *Recorder, value: u64) void {
        self.append(.{ .integer = value });
    }
    pub fn check(self: *const Recorder) !void {
        if (self.failure) |failure| return failure;
    }
    pub fn mixStaticRoot(self: *Recorder, value: [32]u8) void {
        self.mixRoot(value);
    }
    /// Record consumption only. No native draw is performed or returned.
    pub fn skipCommittedRoots(self: *Recorder, count: usize) !void {
        try self.check();
        if (count != 2 and count != 3) return error.InvalidNativeBlake3Transcript;
        return self.skipCommittedRootsFor(count);
    }
    /// Explicit original PAGE eight-root route. Existing word/parent callers
    /// retain the old two/three-root method and its accepted grammar.
    pub fn skipCommittedRootsFor(self: *Recorder, count: usize) !void {
        try self.check();
        if ((count != 2 and count != 3 and count != 8) or self.skipped_roots != 0 or self.operations.items.len == 0)
            return error.InvalidNativeBlake3Transcript;
        self.skipped_roots = count;
    }
    pub fn universalPairs(self: *Recorder, first: usize, count: usize) !void {
        for (first..try std.math.add(usize, first, count)) |index| {
            self.append(.{ .secure = .{ .output = .{ .universal = index }, .attempts = 0, .consumption = .two, .values = @splat(core.fields.m31.M31.zero()) } });
        }
        try self.check();
    }
    pub fn suffix(self: *Recorder, operation: Schema.Operation) !void {
        switch (operation) {
            .commitment => |value| self.mixPublicRoot(value.source, @splat(0)),
            .secure => |value| self.append(.{ .secure = .{ .output = value.role, .attempts = 0, .consumption = if (value.consumption == .one) .one else .two, .values = @splat(core.fields.m31.M31.zero()) } }),
            .claim_frame => |value| {
                self.mixU32s(&value.tag);
                try self.routedFelts(value.source, value.count);
            },
            .sampled_values => |value| try self.routedFelts(value.source, value.count),
            .fri_root => |value| self.mixPublicRoot(value.source, @splat(0)),
            .terminal_coefficients => |value| try self.routedFelts(value.source, value.count),
            .pow => |value| {
                try self.admitWords(2);
                self.append(.{ .pow = .{ .bits = value.bits, .nonce = 0, .nonce_source = value.source } });
            },
            .nonce => |source| self.mixPublicInteger(source, 0),
            .queries => |value| {
                try self.admitWords(value.count);
                const count_only = try self.a.alloc(u32, value.count);
                @memset(count_only, 0);
                self.append(.{ .queries = .{ .log_domain_size = value.log_domain_size, .values = count_only, .export_outputs = true } });
            },
        }
        if (self.failure) |failure| return failure;
    }
};
