//! Streaming source equations. Every private byte/word/clock is bit-ranged.
//! Chunks communicate only through typed LogUp tuples; later proof aggregation
//! must enforce exact chunk coverage and close all routing/byte/state sums.
//! This is an equation/witness path, not a verified source receipt.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const crypto = @import("block_v5_memory_source_crypto_v1.zig");
const protocol = @import("../../prover/block_v5_memory_source_auth_protocol_v1.zig");
const tree = @import("../../air/memory_commitment/blake3_state_tree.zig");
pub const Kind = union(enum) {
    sha: struct { stream: protocol.Stream, block: u64 },
    record: struct { stream: protocol.Stream, ordinal: u64 },
    leaf: struct { edit: protocol.Edit, ordinal: u64 },
    node: struct { edit: protocol.Edit, ordinal: u64, height: u5 },
    root: struct { edit: protocol.Edit, ordinal: u64 },
};
/// Fixed-size chunk envelope: no complete file, image, or sibling array owner.
/// Unused slots are constrained zero, so the witness grammar is canonical.
pub const Witness = struct {
    raw: [64]u8 = @splat(0),
    state: [8]u32 = @splat(0),
    address: u32 = 0,
    previous_address: u32 = 0,
    before: u32 = 0,
    after: u32 = 0,
    clock: u64 = 0,
    before_hash: [32]u8 = @splat(0),
    after_hash: [32]u8 = @splat(0),
    sibling: [32]u8 = @splat(0),
};
pub const BIT_COUNT = 64 * 8 + 8 * 32 + 4 * 32 + 64 + 3 * 256;
pub const SUM_COUNT = std.meta.fields(protocol.Sums).len;
pub const PAIR_COUNT = 11; // source9 + word initial/endpoint
pub const INPUT_COUNT = BIT_COUNT + 2 * PAIR_COUNT + SUM_COUNT;

pub fn validateKind(a: *const protocol.Admitted, kind: Kind) !void {
    try a.require();
    switch (kind) {
        .sha => |s| {
            if (s.block > a.byteLength(s.stream) / 64) return error.InvalidMemorySourceChunk;
        },
        .record => |r| {
            if (r.stream == .public_input or r.ordinal >= a.records(r.stream)) return error.InvalidMemorySourceChunk;
        },
        .leaf => |e| try validateEdit(a, e.edit, e.ordinal),
        .node => |e| {
            try validateEdit(a, e.edit, e.ordinal);
            if (e.height >= tree.DEPTH) return error.InvalidMemorySourceChunk;
        },
        .root => |e| try validateEdit(a, e.edit, e.ordinal),
    }
}
fn validateEdit(a: *const protocol.Admitted, edit: protocol.Edit, ordinal: u64) !void {
    const stream: protocol.Stream = switch (edit) {
        .insert_input => .input_words,
        .insert_rw => .rw_words,
        .update => .endpoints,
    };
    if (ordinal >= a.records(stream)) return error.InvalidMemorySourceChunk;
}
pub fn editIndex(a: *const protocol.Admitted, edit: protocol.Edit, ordinal: u64) u64 {
    return ordinal + switch (edit) {
        .insert_input => @as(u64, 0),
        .insert_rw => a.records(.input_words),
        .update => a.records(.input_words) + a.records(.rw_words),
    };
}
pub fn writeInputs(w: Witness, c: protocol.Challenges, claims: protocol.Sums, out: []Q) !void {
    if (out.len != INPUT_COUNT) return error.InvalidMemorySourceInputs;
    var at: usize = 0;
    for (w.raw) |x| putBits(out, &at, x, 8);
    for (w.state) |x| putBits(out, &at, x, 32);
    for ([_]u32{ w.address, w.previous_address, w.before, w.after }) |x| putBits(out, &at, x, 32);
    putBits(out, &at, w.clock, 64);
    for ([_][32]u8{ w.before_hash, w.after_hash, w.sibling }) |d| for (d) |x| {
        putBits(out, &at, x, 8);
    };
    inline for (.{ c.bytes, c.input, c.insertion, c.before, c.after, c.route, c.roots, c.ordering, c.sha_chain, c.word.initial, c.word.endpoint }) |p| {
        out[at] = p.z;
        out[at + 1] = p.alpha;
        at += 2;
    }
    inline for (std.meta.fields(protocol.Sums)) |field| {
        out[at] = @field(claims, field.name);
        at += 1;
    }
    std.debug.assert(at == out.len);
}
fn putBits(out: []Q, at: *usize, value: u64, count: usize) void {
    for (0..count) |i| {
        out[at.*] = Q.fromBase(M.fromCanonical(@intCast((value >> @intCast(i)) & 1)));
        at.* += 1;
    }
}

pub fn Algebra(comptime S: type) type {
    return struct {
        const Self = @This();
        pub const C = crypto.Algebra(S);
        pub const Pair = struct {
            z: S,
            alpha: S,
            pub fn combine(self: @This(), values: []const S) S {
                var out = S.zero();
                var power = S.one();
                for (values) |value| {
                    out = out.add(power.mul(value));
                    power = power.mul(self.alpha);
                }
                return out.sub(self.z);
            }
        };
        pub const Sums = struct {
            bytes: S,
            input: S,
            insertion: S,
            before: S,
            after: S,
            route: S,
            initial: S,
            endpoint: S,
            roots: S,
            ordering: S,
            sha_chain: S,
            pub fn zero() @This() {
                var out: @This() = undefined;
                inline for (std.meta.fields(@This())) |f| @field(out, f.name) = S.zero();
                return out;
            }
        };
        const Data = struct {
            raw: [64]C.Byte,
            state: C.State,
            address: C.Word,
            previous: C.Word,
            before: C.Word,
            after: C.Word,
            clock: [64]S,
            before_hash: C.Digest,
            after_hash: C.Digest,
            sibling: C.Digest,
            pairs: [PAIR_COUNT]Pair,
        };
        fn take(comptime n: usize, inputs: []const S, at: *usize) [n]S {
            const out = inputs[at.*..][0..n].*;
            at.* += n;
            return out;
        }
        fn data(inputs: []const S) Data {
            var at: usize = 0;
            var out: Data = undefined;
            for (&out.raw) |*x| x.* = take(8, inputs, &at);
            for (&out.state) |*x| x.* = take(32, inputs, &at);
            out.address = take(32, inputs, &at);
            out.previous = take(32, inputs, &at);
            out.before = take(32, inputs, &at);
            out.after = take(32, inputs, &at);
            out.clock = take(64, inputs, &at);
            for (&out.before_hash) |*x| x.* = take(8, inputs, &at);
            for (&out.after_hash) |*x| x.* = take(8, inputs, &at);
            for (&out.sibling) |*x| x.* = take(8, inputs, &at);
            for (&out.pairs) |*p| {
                p.z = inputs[at];
                p.alpha = inputs[at + 1];
                at += 2;
            }
            std.debug.assert(at == BIT_COUNT + 2 * PAIR_COUNT);
            return out;
        }
        fn inverse(value: S) !S {
            return if (@hasDecl(S, "inverse")) value.inverse() else try value.inv();
        }
        fn fraction(pair: Pair, values: []const S) !S {
            return (try inverse(pair.combine(values)));
        }
        fn pack(bits: []const S) S {
            var out = S.zero();
            var factor = S.one();
            for (bits) |b| {
                out = out.add(factor.mul(b));
                factor = factor.add(factor);
            }
            return out;
        }
        fn limbs(comptime n: usize, bits: *const [n * 16]S) [n]S {
            var out: [n]S = undefined;
            for (&out, 0..) |*x, i| x.* = pack(bits[i * 16 ..][0..16]);
            return out;
        }
        fn wide(value: u64) [4]S {
            var out: [4]S = undefined;
            for (&out, 0..) |*x, i| x.* = C.scalar(@intCast((value >> @intCast(16 * i)) & 65535));
            return out;
        }
        fn digestScalars(d: C.Digest) [32]S {
            var out: [32]S = undefined;
            for (&out, d) |*x, b| x.* = pack(&b);
            return out;
        }
        fn bytesBus(pair: Pair, stream: protocol.Stream, offset: u64, raw: []const C.Byte) !S {
            var sum = S.zero();
            for (raw, 0..) |b, i| {
                const tuple = [1]S{C.scalar(@intFromEnum(stream))} ++ wide(offset + i) ++ [1]S{pack(&b)};
                sum = sum.add((try fraction(pair, &tuple)));
            }
            return sum;
        }
        fn nonzero(bits: []const S) S {
            var zero = S.one();
            for (bits) |b| zero = zero.mul(S.one().sub(b));
            return S.one().sub(zero);
        }
        fn less(a: C.Word, b: C.Word) S {
            var equal = S.one();
            var lt = S.zero();
            var i: usize = 32;
            while (i != 0) {
                i -= 1;
                lt = lt.add(equal.mul(S.one().sub(a[i])).mul(b[i]));
                equal = equal.mul(S.one().sub(C.xorBit(a[i], b[i])));
            }
            return lt;
        }
        fn interval(address: C.Word, begin: u32, end: u32) S {
            return S.one().sub(less(address, C.word(begin))).mul(less(address, C.word(end)));
        }
        fn classified(address: C.Word, layout: anytype) S {
            const input = interval(address, layout.input_base, layout.input_end);
            const data_flag = interval(address, layout.data_base, layout.data_end);
            const stack = interval(address, layout.stack_bottom, layout.stack_top);
            const io = interval(address, layout.io_base, layout.io_end);
            const rw = S.one().sub(S.one().sub(data_flag).mul(S.one().sub(stack)).mul(S.one().sub(io)));
            return input.add(S.one().sub(input).mul(rw));
        }
        fn route(pair: Pair, index: u64, level: u32, address: C.Word, before: C.Digest, after: C.Digest) !S {
            const tuple = wide(index) ++ [1]S{C.scalar(level)} ++ limbs(2, &address) ++ digestScalars(before) ++ digestScalars(after);
            return (try fraction(pair, &tuple));
        }
        fn rootTerm(pair: Pair, index: u64, digest: C.Digest) !S {
            const tuple = wide(index) ++ digestScalars(digest);
            return (try fraction(pair, &tuple));
        }
        fn shaTerm(pair: Pair, stream: protocol.Stream, index: u64, state: C.State) !S {
            const tuple = [1]S{C.scalar(@intFromEnum(stream))} ++ wide(index) ++ digestScalars(C.shaDigest(state));
            return (try fraction(pair, &tuple));
        }
        fn equalDigest(sink: anytype, a: C.Digest, b: C.Digest) !void {
            for (a, b) |x, y| for (x, y) |p, q| {
                try sink.zero(p.sub(q));
            };
        }
        fn equalWord(sink: anytype, a: C.Word, b: C.Word) !void {
            for (a, b) |x, y| try sink.zero(x.sub(y));
        }
        fn zeroBits(sink: anytype, bits: []const S) !void {
            for (bits) |b| try sink.zero(b);
        }
        fn addressConstraints(sink: anytype, address: C.Word, layout: anytype) !void {
            try zeroBits(sink, address[0..2]);
            try zeroBits(sink, address[30..32]);
            try sink.zero(classified(address, layout).sub(S.one()));
            try sink.zero(interval(address, layout.program_base, layout.program_end));
        }
        fn canonicalUnused(sink: anytype, d: Data, comptime raw: bool, comptime state: bool, comptime addr: bool, comptime previous: bool, comptime before: bool, comptime after: bool, comptime clock: bool, comptime hashes: bool, comptime sibling: bool) !void {
            if (!raw) for (d.raw) |b| {
                try zeroBits(sink, &b);
            };
            if (!state) for (d.state) |w| {
                try zeroBits(sink, &w);
            };
            if (!addr) try zeroBits(sink, &d.address);
            if (!previous) try zeroBits(sink, &d.previous);
            if (!before) try zeroBits(sink, &d.before);
            if (!after) try zeroBits(sink, &d.after);
            if (!clock) try zeroBits(sink, &d.clock);
            if (!hashes) {
                for (d.before_hash) |b| try zeroBits(sink, &b);
                for (d.after_hash) |b| try zeroBits(sink, &b);
            }
            if (!sibling) for (d.sibling) |b| {
                try zeroBits(sink, &b);
            };
        }
        /// Sink.zero is the exact circuit-constraint interface. Scalar sinks
        /// check the same roots; symbolic sinks record them without a host gate.
        pub fn compute(a: *const protocol.Admitted, kind: Kind, inputs: []const S, sink: anytype) !Self.Sums {
            try validateKind(a, kind);
            if (inputs.len != INPUT_COUNT) return error.InvalidMemorySourceInputs;
            for (inputs[0..BIT_COUNT]) |b| try sink.zero(b.mul(b.sub(S.one())));
            const d = data(inputs);
            var sums = Self.Sums.zero();
            switch (kind) {
                .sha => |s| {
                    try canonicalUnused(sink, d, true, true, false, false, false, false, false, false, false);
                    const length = a.byteLength(s.stream);
                    const offset = s.block * 64;
                    const terminal = s.block == length / 64;
                    const used: usize = if (terminal) @intCast(length % 64) else 64;
                    for (d.raw[used..]) |b| try zeroBits(sink, &b);
                    if (s.block == 0) {
                        const iv = C.shaInitial();
                        for (iv, d.state) |x, y| try equalWord(sink, x, y);
                    }
                    const out = try C.shaChunk(d.state, d.raw, used, length, terminal);
                    if (terminal) try equalDigest(sink, C.shaDigest(out), C.digest(a.digest(s.stream))) else sums.sha_chain = sums.sha_chain.add((try shaTerm(d.pairs[8], s.stream, s.block + 1, out)));
                    if (s.block != 0) sums.sha_chain = sums.sha_chain.sub((try shaTerm(d.pairs[8], s.stream, s.block, d.state)));
                    sums.bytes = (try bytesBus(d.pairs[0], s.stream, offset, d.raw[0..used])).neg();
                    if (s.stream == .public_input) {
                        for (0..(used + 3) / 4) |i| {
                            var bytes: [4]C.Byte = @splat(C.byte(0));
                            const remaining: usize = @min(4, used - i * 4);
                            @memcpy(bytes[0..remaining], d.raw[i * 4 ..][0..remaining]);
                            const value = C.fromBytes(bytes, .little);
                            const address = C.word(@intCast(@as(u64, a.pins.initial.layout.input_base) + offset + i * 4));
                            const tuple = limbs(2, &address) ++ limbs(2, &value);
                            sums.input = sums.input.add(nonzero(&value).mul((try fraction(d.pairs[1], &tuple))));
                        }
                        // Public bytes are not canonical record bytes. Only
                        // the sparse-word link above is consumed downstream.
                        sums.bytes = S.zero();
                    }
                },
                .record => |r| {
                    try canonicalUnused(sink, d, false, false, true, true, true, true, true, false, false);
                    try addressConstraints(sink, d.address, a.pins.initial.layout);
                    if (r.ordinal != 0) try sink.zero(less(d.previous, d.address).sub(S.one())) else try zeroBits(sink, &d.previous);
                    const address_bytes = C.toBytes(d.address, .little);
                    var raw: [16]C.Byte = undefined;
                    var used: usize = undefined;
                    if (r.stream == .input_words or r.stream == .rw_words) {
                        try equalWord(sink, d.before, C.word(0));
                        try zeroBits(sink, &d.clock);
                        try sink.zero(nonzero(&d.after).sub(S.one()));
                        const is_input = interval(d.address, a.pins.initial.layout.input_base, a.pins.initial.layout.input_end);
                        try sink.zero(is_input.sub(C.bit(r.stream == .input_words)));
                        @memcpy(raw[0..4], &address_bytes);
                        @memcpy(raw[4..8], &C.toBytes(d.after, .little));
                        used = 8;
                        const tuple = limbs(2, &d.address) ++ limbs(2, &d.after);
                        if (r.stream == .input_words) sums.input = (try fraction(d.pairs[1], &tuple)).neg();
                        const insertion = [1]S{C.scalar(if (r.stream == .input_words) 1 else 2)} ++ tuple;
                        sums.insertion = (try fraction(d.pairs[2], &insertion));
                    } else if (r.stream == .first_touches) {
                        try equalWord(sink, d.after, C.word(0));
                        try zeroBits(sink, &d.clock);
                        raw[0] = C.byte(1);
                        @memcpy(raw[1..5], &address_bytes);
                        @memcpy(raw[5..9], &C.toBytes(d.before, .little));
                        used = 9;
                        const tuple = limbs(2, &d.address) ++ limbs(2, &d.before);
                        sums.before = (try fraction(d.pairs[3], &tuple));
                        sums.initial = (try fraction(d.pairs[9], &([1]S{S.one()} ++ tuple)));
                    } else {
                        try equalWord(sink, d.before, C.word(0));
                        @memcpy(raw[0..4], &address_bytes);
                        for (0..8) |i| raw[4 + i] = d.clock[i * 8 ..][0..8].*;
                        @memcpy(raw[12..16], &C.toBytes(d.after, .little));
                        used = 16;
                        const tuple = limbs(2, &d.address) ++ limbs(4, &d.clock) ++ limbs(2, &d.after);
                        sums.after = (try fraction(d.pairs[4], &tuple));
                        sums.endpoint = (try fraction(d.pairs[10], &([1]S{S.one()} ++ tuple)));
                    }
                    sums.bytes = (try bytesBus(d.pairs[0], r.stream, r.ordinal * used, raw[0..used]));
                    if (r.ordinal != 0) {
                        const tuple = [1]S{C.scalar(@intFromEnum(r.stream))} ++ wide(r.ordinal - 1) ++ limbs(2, &d.previous);
                        sums.ordering = sums.ordering.sub((try fraction(d.pairs[7], &tuple)));
                    }
                    if (r.ordinal + 1 < a.records(r.stream)) {
                        const tuple = [1]S{C.scalar(@intFromEnum(r.stream))} ++ wide(r.ordinal) ++ limbs(2, &d.address);
                        sums.ordering = sums.ordering.add((try fraction(d.pairs[7], &tuple)));
                    }
                },
                .leaf => |e| {
                    try canonicalUnused(sink, d, false, false, true, false, true, true, true, false, false);
                    try addressConstraints(sink, d.address, a.pins.initial.layout);
                    const before = C.leaf(d.before);
                    const after = C.leaf(d.after);
                    const index = editIndex(a, e.edit, e.ordinal);
                    sums.route = (try route(d.pairs[5], index, 0, d.address, before, after)).neg();
                    if (e.edit == .update) {
                        const first = limbs(2, &d.address) ++ limbs(2, &d.before);
                        const last = limbs(2, &d.address) ++ limbs(4, &d.clock) ++ limbs(2, &d.after);
                        sums.before = (try fraction(d.pairs[3], &first)).neg();
                        sums.after = (try fraction(d.pairs[4], &last)).neg();
                    } else {
                        try equalWord(sink, d.before, C.word(0));
                        try zeroBits(sink, &d.clock);
                        try sink.zero(nonzero(&d.after).sub(S.one()));
                        try sink.zero(interval(d.address, a.pins.initial.layout.input_base, a.pins.initial.layout.input_end).sub(C.bit(e.edit == .insert_input)));
                        const tuple = [1]S{C.scalar(@intFromEnum(e.edit))} ++ limbs(2, &d.address) ++ limbs(2, &d.after);
                        sums.insertion = (try fraction(d.pairs[2], &tuple)).neg();
                    }
                },
                .node => |e| {
                    try canonicalUnused(sink, d, false, false, true, false, false, false, false, true, true);
                    try addressConstraints(sink, d.address, a.pins.initial.layout);
                    const side = if (e.height < 28) d.address[@as(usize, e.height) + 2] else S.zero();
                    if (e.height >= 28) {
                        const hasher = tree.TreeHasher.init(.memory);
                        try equalDigest(sink, d.sibling, C.digest(hasher.defaults[tree.DEPTH - @as(usize, e.height)].bytes));
                    }
                    // The SAME sibling variables and SAME side bit enter both
                    // hashes. A before/after path swap cannot delete untouched
                    // leaves or authenticate a different address.
                    const before = C.node(C.select(side, d.before_hash, d.sibling), C.select(side, d.sibling, d.before_hash));
                    const after = C.node(C.select(side, d.after_hash, d.sibling), C.select(side, d.sibling, d.after_hash));
                    const index = editIndex(a, e.edit, e.ordinal);
                    sums.route = (try route(d.pairs[5], index, e.height, d.address, d.before_hash, d.after_hash)).sub((try route(d.pairs[5], index, @as(u32, e.height) + 1, d.address, before, after)));
                },
                .root => |e| {
                    try canonicalUnused(sink, d, false, false, true, false, false, false, false, true, false);
                    try addressConstraints(sink, d.address, a.pins.initial.layout);
                    const index = editIndex(a, e.edit, e.ordinal);
                    const insertions = a.records(.input_words) + a.records(.rw_words);
                    const total = insertions + a.records(.endpoints);
                    if (index == 0) {
                        const hasher = tree.TreeHasher.init(.memory);
                        try equalDigest(sink, d.before_hash, C.digest(hasher.defaults[0].bytes));
                    }
                    if (index + 1 == insertions) try equalDigest(sink, d.after_hash, C.digest(a.pins.initial.initial_rw_root));
                    if (index == insertions) try equalDigest(sink, d.before_hash, C.digest(a.pins.initial.initial_rw_root));
                    if (index + 1 == total) try equalDigest(sink, d.after_hash, C.digest(a.pins.expected_final_rw_root));
                    sums.route = (try route(d.pairs[5], index, tree.DEPTH, d.address, d.before_hash, d.after_hash));
                    sums.roots = (try rootTerm(d.pairs[6], index + 1, d.after_hash)).sub((try rootTerm(d.pairs[6], index, d.before_hash)));
                },
            }
            return sums;
        }
        pub fn evaluate(a: *const protocol.Admitted, kind: Kind, inputs: []const S, sink: anytype) !Self.Sums {
            const sums = try compute(a, kind, inputs, sink);
            const claims = inputs[BIT_COUNT + 2 * PAIR_COUNT ..];
            inline for (std.meta.fields(Self.Sums), 0..) |f, i| try sink.zero(@field(sums, f.name).sub(claims[i]));
            return sums;
        }
        /// Final aggregator equations, not a host acceptance function. Each
        /// aggregate input must be the sum of freshly proved chunk outputs.
        pub fn closure(a: *const protocol.Admitted, pairs: [PAIR_COUNT]Pair, sums: Self.Sums, expected_initial: S, expected_endpoint: S, sink: anytype) !void {
            inline for (.{ "bytes", "input", "insertion", "before", "after", "route", "ordering", "sha_chain" }) |name| try sink.zero(@field(sums, name));
            try sink.zero(sums.initial.sub(expected_initial));
            try sink.zero(sums.endpoint.sub(expected_endpoint));
            const count = a.records(.input_words) + a.records(.rw_words) + a.records(.endpoints);
            const hasher = tree.TreeHasher.init(.memory);
            const target = (try rootTerm(pairs[6], count, C.digest(a.pins.expected_final_rw_root))).sub((try rootTerm(pairs[6], 0, C.digest(hasher.defaults[0].bytes))));
            try sink.zero(sums.roots.sub(target));
            if (a.records(.input_words) + a.records(.rw_words) == 0) try equalDigest(sink, C.digest(a.pins.initial.initial_rw_root), C.digest(hasher.defaults[0].bytes));
            if (a.records(.endpoints) == 0) try equalDigest(sink, C.digest(a.pins.initial.initial_rw_root), C.digest(a.pins.expected_final_rw_root));
        }
    };
}
