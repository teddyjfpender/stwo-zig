//! Fresh process producer/receiver for the real five-roster graph reference.
const std = @import("std");
const Core = @import("stwo_core");
const P = @import("poseidon2_outer/proof.zig");
const A = @import("poseidon2_outer/authority.zig");
const L = @import("poseidon2_outer/layout.zig");
const a = std.heap.page_allocator;
const HEADER = 200;
fn expected() A.Q {
    var input: [24]A.M = undefined;
    for (&input, 0..) |*v, i| v.* = A.M.fromCanonical(@intCast(137 + 41 * i));
    var first = input;
    Core.crypto.poseidon2_m31_w24.permute(&first);
    var second = first;
    second[0] = first[7];
    second[1] = first[7];
    Core.crypto.poseidon2_m31_w24.permute(&second);
    return A.Q.fromBase(second[7].add(first[7]).mul(input[3]));
}
pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len == 4 and std.mem.eql(u8, args[1], "--produce")) {
        const mutation = std.meta.stringToEnum(P.Mutation, args[2]) orelse return error.UnknownMutation;
        var ctx = try P.fixture(a, false);
        defer ctx.deinit();
        var key = try P.Authority.init(a, &ctx);
        defer key.deinit();
        const bytes = P.proveMutation(a, &ctx, &key, &.{expected()}, mutation) catch |err| {
            std.debug.print("P2_FIVE_PRODUCER_REJECT {s}\n", .{@errorName(err)});
            return err;
        };
        defer a.free(bytes);
        try std.fs.cwd().writeFile(.{ .sub_path = args[3], .data = bytes });
        std.debug.print("P2_FIVE_PRODUCED bytes={} mass={} rows={any} profile={s} production=false\n", .{ bytes.len, key.gather_mass, key.rows, A.MC.protocol_name });
        return;
    }
    if (args.len == 3 and (std.mem.eql(u8, args[1], "--verify") or std.mem.eql(u8, args[1], "--verify-wrong-public"))) {
        var source = try P.fixture(a, true);
        defer source.deinit();
        var key = try P.Authority.init(a, &source);
        defer key.deinit();
        const bytes = try std.fs.cwd().readFileAlloc(a, args[2], 64 << 20);
        defer a.free(bytes);
        const output = if (std.mem.eql(u8, args[1], "--verify")) expected() else expected().add(A.Q.one());
        P.verify(a, &key, &.{output}, bytes) catch |err| {
            std.debug.print("P2_FIVE_RECEIVER_REJECT {s}\n", .{@errorName(err)});
            return err;
        };
        std.debug.print("P2_FIVE_FRESH_OK bytes={} source_rederived=true profile={s}\n", .{ bytes.len, A.MC.protocol_name });
        return;
    }
    if (args.len == 5 and std.mem.eql(u8, args[1], "--tamper-proof")) {
        const bytes = try std.fs.cwd().readFileAlloc(a, args[3], 64 << 20);
        defer a.free(bytes);
        const mutation = args[2];
        if (std.mem.eql(u8, mutation, "claim_balanced")) {
            const out = try a.dupe(u8, bytes);
            defer a.free(out);
            for ([_]usize{ 0, 3 }) |i| {
                var coords: [8]A.M = undefined;
                for (&coords, 0..) |*v, j| v.* = A.M.fromCanonical(std.mem.readInt(u32, out[40 + 32 * i + 4 * j ..][0..4], .little));
                const old = A.O.fromM31Array(coords);
                const value = if (i == 0) old.add(A.O.one()) else old.sub(A.O.one());
                for (value.toM31Array(), 0..) |v, j| std.mem.writeInt(u32, out[40 + 32 * i + 4 * j ..][0..4], v.v, .little);
            }
            try std.fs.cwd().writeFile(.{ .sub_path = args[4], .data = out });
            return;
        }
        if (std.mem.eql(u8, mutation, "magic")) {
            const out = try a.dupe(u8, bytes);
            defer a.free(out);
            out[0] ^= 1;
            try std.fs.cwd().writeFile(.{ .sub_path = args[4], .data = out });
            return;
        }
        if (std.mem.eql(u8, mutation, "trailing")) {
            const out = try a.alloc(u8, bytes.len + 1);
            defer a.free(out);
            @memcpy(out[0..bytes.len], bytes);
            out[bytes.len] = 0;
            try std.fs.cwd().writeFile(.{ .sub_path = args[4], .data = out });
            return;
        }
        var proof = try P.Wire.decodeProofBytesBinary(a, bytes[HEADER..]);
        defer proof.deinit(a);
        if (std.mem.eql(u8, mutation, "fixed_root")) {
            const ptr = proof.commitment_scheme_proof.commitments.items[0][0..4];
            const old = std.mem.readInt(u32, ptr, .little);
            std.mem.writeInt(u32, ptr, if (old == Core.fields.m31.Modulus - 1) 0 else old + 1, .little);
        } else {
            const location: [2]usize = if (std.mem.eql(u8, mutation, "x2")) .{ 1, A.MAIN_START[3] + L.TEMPORARY } else if (std.mem.eql(u8, mutation, "x5")) .{ 1, A.MAIN_START[3] + L.TEMPORARY + 1 } else if (std.mem.eql(u8, mutation, "output_port")) .{ 1, A.MAIN_START[3] + L.OUTPUT + 7 } else if (std.mem.eql(u8, mutation, "multiplicity")) .{ 0, A.FIXED_START[3] + L.OUTPUT_USES + 7 } else if (std.mem.eql(u8, mutation, "range")) .{ 1, A.MAIN_START[4] } else if (std.mem.eql(u8, mutation, "prefix")) .{ 2, A.INTER_START[3] + 23 * 8 } else return error.UnknownMutation;
            const value = &proof.commitment_scheme_proof.queried_values.items[location[0]][location[1]][0];
            value.* = value.add(A.M.one());
        }
        const body = try P.Wire.encodeProofBytesBinary(a, proof);
        defer a.free(body);
        const out = try a.alloc(u8, HEADER + body.len);
        defer a.free(out);
        @memcpy(out[0..HEADER], bytes[0..HEADER]);
        @memcpy(out[HEADER..], body);
        try std.fs.cwd().writeFile(.{ .sub_path = args[4], .data = out });
        return;
    }
    return error.UsagePoseidonGraphFixture;
}
