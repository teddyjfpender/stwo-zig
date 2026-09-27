//! Simultaneous sparse-fold operation equations. Every operand/state bit is
//! ranged; source joins use the ORIGINAL insertion/before/after schemas.
//! Tree/default/hash claims need actual proofs and global exact closure, not
//! acceptance of a host-generated descriptor or a root match alone.
const std = @import("std");
const Defaults = @import("../../prover/block_v5_memory_source_batch_defaults_v1.zig");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Tree = @import("../../air/memory_commitment/blake3_state_tree.zig");
const Crypto = @import("block_v5_memory_source_crypto_v1.zig");
const Protocol = @import("../../prover/block_v5_memory_source_batch_protocol_v1.zig");
const Fold = @import("../../prover/block_v5_memory_source_batch_fold_v1.zig");
// index,address,before,after,full clock,image/touch ordinals; output and children;
// input-image/RW-image/touched; all unused cells must be zero.
pub const BIT_COUNT = 4 * 32 + 3 * 64 + 6 * 256 + 3;
pub const Descriptor = struct {
    kind: Fold.Kind,
    height: u32,
    pub fn validate(self: Descriptor) !void {
        if (self.height > Tree.DEPTH or (self.kind == .leaf and self.height != 0) or (self.kind == .branch and self.height == 0) or (self.kind == .root and self.height != Tree.DEPTH)) return error.InvalidSourceFoldDescriptor;
    }
};
pub fn writeInputs(operation: Fold.Operation, inputs: []Q) !void {
    if (inputs.len != BIT_COUNT) return error.InvalidSourceFoldInputs;
    var at: usize = 0;
    for ([_]u32{ operation.coordinate.index, operation.leaf.address, operation.leaf.before, operation.leaf.after }) |value| putBits(inputs, &at, value, 32);
    putBits(inputs, &at, operation.leaf.clock, 64);
    putBits(inputs, &at, operation.leaf.image_ordinal, 64);
    putBits(inputs, &at, operation.leaf.touch_ordinal, 64);
    for ([_][32]u8{ operation.value.before, operation.value.after, operation.left.before, operation.left.after, operation.right.before, operation.right.after }) |digest| for (digest) |byte| putBits(inputs, &at, byte, 8);
    putBits(inputs, &at, @intFromBool(operation.leaf.image == .input), 1);
    putBits(inputs, &at, @intFromBool(operation.leaf.image == .rw), 1);
    putBits(inputs, &at, @intFromBool(operation.leaf.touched), 1);
    std.debug.assert(at == inputs.len);
}
fn putBits(inputs: []Q, at: *usize, value: u64, count: usize) void {
    for (0..count) |i| {
        inputs[at.*] = Q.fromBase(M.fromCanonical(@intCast((value >> @intCast(i)) & 1)));
        at.* += 1;
    }
}
pub fn Algebra(comptime S: type) type {
    return struct {
        const Self = @This();
        const C = Crypto.Algebra(S);
        pub const Pair = struct {
            z: S,
            alpha: S,
            pub fn combine(self: @This(), values: []const S) S {
                var sum = S.zero();
                var power = S.one();
                for (values) |value| {
                    sum = sum.add(value.mul(power));
                    power = power.mul(self.alpha);
                }
                return sum.sub(self.z);
            }
        };
        pub const Challenges = struct { insertion: Pair, before: Pair, after: Pair, route: Pair, hash: Pair, indexed: Pair };
        pub const Sums = struct {
            indexed: S = S.zero(),
            insertion: S = S.zero(),
            before: S = S.zero(),
            after: S = S.zero(),
            route: S = S.zero(),
            hash: S = S.zero(),
            input: S = S.zero(),
            rw: S = S.zero(),
            touches: S = S.zero(),
            roots: S = S.zero(),
        };
        const Data = struct { index: C.Word, address: C.Word, before: C.Word, after: C.Word, clock: [64]S, image_ordinal: [64]S, touch_ordinal: [64]S, output_before: C.Digest, output_after: C.Digest, left_before: C.Digest, left_after: C.Digest, right_before: C.Digest, right_after: C.Digest, is_input: S, is_rw: S, touched: S };
        fn decode(inputs: []const S) !Data {
            if (inputs.len != BIT_COUNT) return error.InvalidSourceFoldInputs;
            var at: usize = 0;
            var out: Data = undefined;
            inline for (.{ "index", "address", "before", "after" }) |name| {
                @field(out, name) = inputs[at..][0..32].*;
                at += 32;
            }
            out.clock = inputs[at..][0..64].*;
            at += 64;
            out.image_ordinal = inputs[at..][0..64].*;
            at += 64;
            out.touch_ordinal = inputs[at..][0..64].*;
            at += 64;
            inline for (.{ "output_before", "output_after", "left_before", "left_after", "right_before", "right_after" }) |name| {
                for (&@field(out, name)) |*byte| {
                    byte.* = inputs[at..][0..8].*;
                    at += 8;
                }
            }
            out.is_input = inputs[at];
            out.is_rw = inputs[at + 1];
            out.touched = inputs[at + 2];
            return out;
        }
        fn lift(value: Q) S {
            return if (S == Q) value else S.fromSecure(value);
        }
        pub fn challenges(input: Protocol.Challenges) Self.Challenges {
            return .{ .insertion = .{ .z = lift(input.source.insertion.z), .alpha = lift(input.source.insertion.alpha) }, .before = .{ .z = lift(input.source.before.z), .alpha = lift(input.source.before.alpha) }, .after = .{ .z = lift(input.source.after.z), .alpha = lift(input.source.after.alpha) }, .route = .{ .z = lift(input.route.z), .alpha = lift(input.route.alpha) }, .hash = .{ .z = lift(input.hash.z), .alpha = lift(input.hash.alpha) }, .indexed = .{ .z = lift(input.indexed.z), .alpha = lift(input.indexed.alpha) } };
        }
        fn scalar(value: u32) S {
            return S.fromBase(M.fromCanonical(value));
        }
        fn pack(bits: []const S) S {
            var sum = S.zero();
            var weight = S.one();
            for (bits) |bit| {
                sum = sum.add(weight.mul(bit));
                weight = weight.add(weight);
            }
            return sum;
        }
        fn limbs(comptime n: usize, bits: *const [n * 16]S) [n]S {
            var out: [n]S = undefined;
            for (&out, 0..) |*value, i| value.* = pack(bits[i * 16 ..][0..16]);
            return out;
        }
        fn digestBytes(input: C.Digest) [32]S {
            var out: [32]S = undefined;
            for (&out, input) |*value, byte| value.* = pack(&byte);
            return out;
        }
        fn fraction(pair: Self.Pair, values: []const S) !S {
            const denom = pair.combine(values);
            return if (@hasDecl(S, "inverse")) denom.inverse() else try denom.inv();
        }
        fn zeroBits(sink: anytype, values: []const S) !void {
            for (values) |value| try sink.zero(value);
        }
        fn equalDigest(sink: anytype, a: C.Digest, b: C.Digest) !void {
            for (a, b) |x, y| for (x, y) |p, q| try sink.zero(p.sub(q));
        }
        fn equalWord(sink: anytype, a: C.Word, b: C.Word) !void {
            for (a, b) |x, y| try sink.zero(x.sub(y));
        }
        fn nonzero(bits: []const S) S {
            var product = S.one();
            for (bits) |bit| product = product.mul(S.one().sub(bit));
            return S.one().sub(product);
        }
        fn less(a: C.Word, b: C.Word) S {
            var equal = S.one();
            var result = S.zero();
            var i: usize = 32;
            while (i != 0) {
                i -= 1;
                result = result.add(equal.mul(S.one().sub(a[i])).mul(b[i]));
                equal = equal.mul(S.one().sub(C.xorBit(a[i], b[i])));
            }
            return result;
        }
        fn interval(address: C.Word, begin: u32, end: u32) S {
            return S.one().sub(less(address, C.word(begin))).mul(less(address, C.word(end)));
        }
        fn wideBits(value: u64) [64]S {
            var out: [64]S = undefined;
            for (&out, 0..) |*bit, i| bit.* = scalar(@intCast((value >> @intCast(i)) & 1));
            return out;
        }
        fn lessWide(a: [64]S, b: [64]S) S {
            var equal = S.one();
            var out = S.zero();
            var i: usize = 64;
            while (i != 0) {
                i -= 1;
                out = out.add(equal.mul(S.one().sub(a[i])).mul(b[i]));
                equal = equal.mul(S.one().sub(C.xorBit(a[i], b[i])));
            }
            return out;
        }
        fn indexed(pair: Self.Pair, stream: u32, ordinal: [64]S, address: C.Word, value: C.Word, clock: [64]S) !S {
            return fraction(pair, &([1]S{scalar(stream)} ++ limbs(4, &ordinal) ++ limbs(2, &address) ++ limbs(2, &value) ++ limbs(4, &clock)));
        }
        /// Companion to an ORIGINAL independently admitted record equation.
        /// Caller must also prove that record equation on these SAME committed
        /// source bits; this extra sum alone is not byte/SHA authentication.
        pub fn indexedRecord(stream: @import("../../prover/block_v5_memory_source_auth_protocol_v1.zig").Stream, ordinal: u64, original: []const S, challenge: Self.Pair) !S {
            const Old = @import("block_v5_memory_source_equations_v1.zig");
            comptime {
                if (Old.BIT_COUNT != 1728) @compileError("original source bit layout changed: indexed record mapping needs re-admission");
            }
            if (original.len != Old.INPUT_COUNT or stream == .public_input) return error.InvalidSourceFoldInputs;
            const address = original[768..800].*;
            const before = original[832..864].*;
            const after = original[864..896].*;
            const clock = original[896..960].*;
            return indexed(challenge, @intFromEnum(stream), wideBits(ordinal), address, if (stream == .first_touches) before else after, if (stream == .endpoints) clock else @splat(S.zero()));
        }
        fn route(pair: Self.Pair, height: u32, index: C.Word, before: C.Digest, after: C.Digest) !S {
            return fraction(pair, &([1]S{scalar(height)} ++ limbs(2, &index) ++ digestBytes(before) ++ digestBytes(after)));
        }
        pub fn hashTerm(pair: Self.Pair, tag: u32, payload: [64]C.Byte, digest: C.Digest) !S {
            var bytes: [64]S = undefined;
            for (&bytes, payload) |*value, byte| value.* = pack(&byte);
            return fraction(pair, &([1]S{scalar(tag)} ++ bytes ++ digestBytes(digest)));
        }
        fn unusedLeaf(sink: anytype, d: Data) !void {
            try zeroBits(sink, &d.address);
            try zeroBits(sink, &d.before);
            try zeroBits(sink, &d.after);
            try zeroBits(sink, &d.clock);
            try zeroBits(sink, &d.image_ordinal);
            try zeroBits(sink, &d.touch_ordinal);
            try sink.zero(d.is_input);
            try sink.zero(d.is_rw);
            try sink.zero(d.touched);
        }
        fn unusedChildren(sink: anytype, d: Data) !void {
            for ([_]C.Digest{ d.left_before, d.left_after, d.right_before, d.right_after }) |digest| for (digest) |byte| try zeroBits(sink, &byte);
        }
        /// Hash-mode oracle computes the exact cryptographic equation; packed
        /// mode emits the same fully framed request that must close against
        /// PackedHash.Algebra and genuine G/XOR/table proofs. No mode mints a
        /// receipt. This mode belongs in the new proof ABI, never payload data.
        pub fn compute(comptime hash_oracle: bool, admitted: *const Protocol.Admission, descriptor: Descriptor, inputs: []const S, c: Self.Challenges, sink: anytype) !Self.Sums {
            try descriptor.validate();
            const d = try decode(inputs);
            for (inputs) |value| try sink.zero(value.mul(value.sub(S.one())));
            // A coordinate's legal index bits are independently constrained;
            // upper two word-index bits at leaves remain fixed empty topology.
            try zeroBits(sink, d.index[Tree.DEPTH - descriptor.height .. 32]);
            var out = Self.Sums{};
            switch (descriptor.kind) {
                .empty => {
                    try unusedLeaf(sink, d);
                    try unusedChildren(sink, d);
                    const defaults = Defaults.get();
                    try equalDigest(sink, d.output_before, C.digest(defaults.defaults[Tree.DEPTH - descriptor.height].bytes));
                    try equalDigest(sink, d.output_after, d.output_before);
                },
                .leaf => {
                    try unusedChildren(sink, d);
                    try zeroBits(sink, d.address[0..2]);
                    try zeroBits(sink, d.address[30..32]);
                    for (0..28) |i| try sink.zero(d.index[i].sub(d.address[i + 2]));
                    try zeroBits(sink, d.index[28..32]);
                    const layout = admitted.source.pins.initial.layout;
                    const input = interval(d.address, layout.input_base, layout.input_end);
                    const data = interval(d.address, layout.data_base, layout.data_end);
                    const stack = interval(d.address, layout.stack_bottom, layout.stack_top);
                    const io = interval(d.address, layout.io_base, layout.io_end);
                    const rw = S.one().sub(S.one().sub(data).mul(S.one().sub(stack)).mul(S.one().sub(io)));
                    try sink.zero(rw.sub(S.one()));
                    try sink.zero(interval(d.address, layout.program_base, layout.program_end));
                    try sink.zero(d.is_input.mul(d.is_rw));
                    const image = d.is_input.add(d.is_rw);
                    try sink.zero(S.one().sub(image).mul(S.one().sub(d.touched)));
                    try sink.zero(d.is_input.mul(input.sub(S.one())));
                    try sink.zero(d.is_rw.mul(input));
                    try sink.zero(image.mul(nonzero(&d.before).sub(S.one())));
                    for (d.before) |bit| try sink.zero(S.one().sub(image).mul(bit));
                    for (d.before, d.after) |before, after| {
                        try sink.zero(S.one().sub(d.touched).mul(after.sub(before)));
                    }
                    for (d.clock) |bit| try sink.zero(S.one().sub(d.touched).mul(bit));
                    // Exact old Source9 tuples permit sharing the original
                    // independently SHA-authenticated record proofs.
                    const address_value = limbs(2, &d.address) ++ limbs(2, &d.before);
                    out.insertion = d.is_input.mul(try fraction(c.insertion, &([1]S{scalar(1)} ++ address_value))).add(d.is_rw.mul(try fraction(c.insertion, &([1]S{scalar(2)} ++ address_value)))).neg();
                    out.before = d.touched.mul(try fraction(c.before, &address_value)).neg();
                    out.after = d.touched.mul(try fraction(c.after, &(limbs(2, &d.address) ++ limbs(4, &d.clock) ++ limbs(2, &d.after)))).neg();
                    for (d.image_ordinal) |bit| try sink.zero(S.one().sub(image).mul(bit));
                    for (d.touch_ordinal) |bit| try sink.zero(S.one().sub(d.touched).mul(bit));
                    try sink.zero(d.is_input.mul(S.one().sub(lessWide(d.image_ordinal, wideBits(admitted.source.records(.input_words))))));
                    try sink.zero(d.is_rw.mul(S.one().sub(lessWide(d.image_ordinal, wideBits(admitted.source.records(.rw_words))))));
                    try sink.zero(d.touched.mul(S.one().sub(lessWide(d.touch_ordinal, wideBits(admitted.source.records(.endpoints))))));
                    const zero_clock: [64]S = @splat(S.zero());
                    out.indexed = d.is_input.mul(try indexed(c.indexed, 2, d.image_ordinal, d.address, d.before, zero_clock)).add(d.is_rw.mul(try indexed(c.indexed, 3, d.image_ordinal, d.address, d.before, zero_clock))).add(d.touched.mul(try indexed(c.indexed, 4, d.touch_ordinal, d.address, d.before, zero_clock))).add(d.touched.mul(try indexed(c.indexed, 5, d.touch_ordinal, d.address, d.after, d.clock))).neg();
                    out.input = d.is_input;
                    out.rw = d.is_rw;
                    out.touches = d.touched;
                    if (hash_oracle) {
                        try equalDigest(sink, d.output_before, C.leaf(d.before));
                        try equalDigest(sink, d.output_after, C.leaf(d.after));
                    }
                    var before_payload: [64]C.Byte = @splat(C.byte(0));
                    @memcpy(before_payload[0..4], &C.toBytes(d.before, .little));
                    var after_payload: [64]C.Byte = @splat(C.byte(0));
                    @memcpy(after_payload[0..4], &C.toBytes(d.after, .little));
                    // Both requests remain exact; equal/default computation
                    // can be shared by a provider with proved multiplicity2.
                    out.hash = (try hashTerm(c.hash, 1, before_payload, d.output_before)).add(try hashTerm(c.hash, 1, after_payload, d.output_after));
                },
                .branch => {
                    try unusedLeaf(sink, d);
                    if (hash_oracle) {
                        try equalDigest(sink, d.output_before, C.node(d.left_before, d.right_before));
                        try equalDigest(sink, d.output_after, C.node(d.left_after, d.right_after));
                    }
                    var before_payload: [64]C.Byte = undefined;
                    @memcpy(before_payload[0..32], &d.left_before);
                    @memcpy(before_payload[32..64], &d.right_before);
                    var after_payload: [64]C.Byte = undefined;
                    @memcpy(after_payload[0..32], &d.left_after);
                    @memcpy(after_payload[32..64], &d.right_after);
                    out.hash = (try hashTerm(c.hash, 2, before_payload, d.output_before)).add(try hashTerm(c.hash, 2, after_payload, d.output_after));
                    var left: C.Word = @splat(S.zero());
                    var right: C.Word = @splat(S.zero());
                    for (0..31) |i| {
                        left[i + 1] = d.index[i];
                        right[i + 1] = d.index[i];
                    }
                    right[0] = S.one();
                    out.route = (try route(c.route, descriptor.height - 1, left, d.left_before, d.left_after)).neg().sub(try route(c.route, descriptor.height - 1, right, d.right_before, d.right_after));
                },
                .root => {
                    try unusedLeaf(sink, d);
                    try unusedChildren(sink, d);
                    try zeroBits(sink, &d.index);
                    try equalDigest(sink, d.output_before, C.digest(admitted.source.pins.initial.initial_rw_root));
                    try equalDigest(sink, d.output_after, C.digest(admitted.source.pins.expected_final_rw_root));
                    out.route = (try route(c.route, Tree.DEPTH, d.index, d.output_before, d.output_after)).neg();
                    out.roots = S.one();
                },
            }
            if (descriptor.kind != .root) out.route = out.route.add(try route(c.route, descriptor.height, d.index, d.output_before, d.output_after));
            return out;
        }
        pub fn closure(admitted: *const Protocol.Admission, totals: Self.Sums, hash_provider_sum: S, source_records: Self.Sums, sink: anytype) !void {
            inline for (.{ "indexed", "insertion", "before", "after" }) |name| try sink.zero(@field(totals, name).add(@field(source_records, name)));
            try sink.zero(totals.route);
            try sink.zero(totals.hash.add(hash_provider_sum));
            const required = try Protocol.Required.fromAdmission(admitted);
            try sink.zero(totals.input.sub(scalar(@intCast(required.input))));
            try sink.zero(totals.rw.sub(scalar(@intCast(required.rw))));
            try sink.zero(totals.touches.sub(scalar(@intCast(required.touches))));
            try sink.zero(totals.roots.sub(S.one()));
        }
    };
}
