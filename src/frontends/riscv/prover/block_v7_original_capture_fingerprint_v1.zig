//! Request-local content binding for already freshly verified originals. This
//! digest is not proof authority: it prevents substituting another candidate
//! after verification while the owned capture is handed to recursive planning.
const std = @import("std");
const core = @import("stwo_core");
const Fields = @import("block_v7_union_claim_wire_v1.zig");
pub const Kind = enum(u8) { native, caller, caller_active, program, lookup, memory, window_memory };
pub const Limits = struct { max_bytes: usize = 1 << 30, max_claim_items: usize = 1 << 24 };
const Sink = struct {
    hash: std.crypto.hash.sha2.Sha256 = .init(.{}),
    remaining: usize,
    pub fn writeAll(self: *Sink, bytes: []const u8) !void {
        if (bytes.len > self.remaining) return error.CaptureFingerprintResourceLimit;
        self.remaining -= bytes.len;
        self.hash.update(bytes);
    }
    pub fn writeByte(self: *Sink, value: u8) !void {
        try self.writeAll(&.{value});
    }
    pub fn writeClaim(self: *Sink, value: core.fields.qm31.QM31) !void {
        for (value.toM31Array()) |limb| {
            if (limb.v >= core.fields.m31.Modulus) return error.NonCanonicalM31;
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, limb.v, .little);
            try self.writeAll(&bytes);
        }
    }
    fn fields(self: *Sink, value: anytype, items: *usize) !void {
        try Fields.encode(@TypeOf(value), self, value, items);
    }
};
pub fn compute(comptime kind: Kind, proof: anytype, limits: Limits) ![32]u8 {
    var sink = Sink{ .remaining = limits.max_bytes };
    var items = limits.max_claim_items;
    try sink.writeAll("stwo-v7-verified-original-content-v1");
    try sink.writeByte(@intFromEnum(kind));
    switch (kind) {
        .native => {
            try sink.fields(proof.claims, &items);
            try sink.fields(proof.memory_claims, &items);
        },
        .caller, .caller_active => {
            try sink.fields(proof.arithmetic, &items);
            try sink.fields(proof.relations, &items);
        },
        .program => try sink.fields(proof.claim, &items),
        .lookup => try sink.fields(proof.claims, &items),
        .memory, .window_memory => {
            try sink.fields(proof.roots, &items);
            try sink.fields(proof.interval_log, &items);
            try sink.fields(proof.ram, &items);
            try sink.fields(proof.interval, &items);
            try sink.fields(proof.range16, &items);
            if (kind == .memory) try sink.fields(proof.terminal, &items);
        },
    }
    try @import("interop_postcard").serializeProof(core.proof_suites.Blake3.Hasher, &sink, proof.stark);
    return sink.hash.finalResult();
}
