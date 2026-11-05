//! Scoped dedicated-row producer and independently reconstructed receiver.
const std = @import("std");
const F = @import("poseidon2_outer/stark_fixture.zig");
const a = std.heap.page_allocator;
pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len == 4 and std.mem.eql(u8, args[1], "--produce")) {
        const mutation = std.meta.stringToEnum(F.Mutation, args[2]) orelse return error.InvalidPoseidonFixtureMutation;
        var proof = F.produce(a, mutation) catch |err| {
            std.debug.print("P2_DEDICATED_ROW_PRODUCER_REJECT {s}\n", .{@errorName(err)});
            return err;
        };
        defer proof.deinit(a);
        const bytes = try F.Wire.encodeProofBytesBinary(a, proof.proof);
        defer a.free(bytes);
        try std.fs.cwd().writeFile(.{ .sub_path = args[3], .data = bytes });
        std.debug.print("P2_DEDICATED_ROW_PRODUCED mutation={s} rows={} main={} fixed={} roots={} bytes={}\n", .{ @tagName(mutation), F.ROWS, F.MAIN, F.FIXED, F.ROOTS, bytes.len });
        return;
    }
    if (args.len == 5 and std.mem.eql(u8, args[1], "--tamper-proof")) {
        const bytes = try std.fs.cwd().readFileAlloc(a, args[3], 64 << 20);
        defer a.free(bytes);
        var proof = try F.Wire.decodeProofBytesBinary(a, bytes);
        defer proof.deinit(a);
        if (std.mem.eql(u8, args[2], "fixed_root")) {
            const word = std.mem.readInt(u32, proof.commitment_scheme_proof.commitments.items[0][0..4], .little);
            const changed = if (word == @import("stwo_core").fields.m31.Modulus - 1) 0 else word + 1;
            std.mem.writeInt(u32, proof.commitment_scheme_proof.commitments.items[0][0..4], changed, .little);
        } else {
            const mutation = std.meta.stringToEnum(F.Mutation, args[2]) orelse return error.InvalidPoseidonFixtureMutation;
            const l = @import("poseidon2_outer/layout.zig");
            const tree: usize = if (mutation == .fixed_id) 0 else 1;
            const column: usize = switch (mutation) {
                .x2 => l.TEMPORARY,
                .x5 => l.TEMPORARY + 1,
                .port_address => F.PORT_BASE + 5 * 7,
                .port_extension => F.PORT_BASE + 5 * 31 + 2,
                .fixed_id => l.INPUT_ID,
                .none => return error.InvalidPoseidonFixtureMutation,
            };
            const value = &proof.commitment_scheme_proof.queried_values.items[tree][column][0];
            value.* = value.add(@import("stwo_core").fields.m31.M31.one());
        }
        const encoded = try F.Wire.encodeProofBytesBinary(a, proof);
        defer a.free(encoded);
        try std.fs.cwd().writeFile(.{ .sub_path = args[4], .data = encoded });
        return;
    }
    const bad_public = args.len == 3 and std.mem.eql(u8, args[1], "--verify-wrong-public");
    if (args.len == 3 and (bad_public or std.mem.eql(u8, args[1], "--verify"))) {
        const bytes = try std.fs.cwd().readFileAlloc(a, args[2], 64 << 20);
        defer a.free(bytes);
        var statement = F.Statement.fixture();
        if (bad_public) statement.output[0] = statement.output[0].add(@import("stwo_core").fields.m31.M31.one());
        F.verify(a, try F.Wire.decodeProofBytesBinary(a, bytes), statement) catch |err| {
            std.debug.print("P2_DEDICATED_ROW_REJECT {s}\n", .{@errorName(err)});
            return err;
        };
        std.debug.print("P2_DEDICATED_ROW_FRESH_OK rows={} main={} fixed={} roots={} bytes={}\n", .{ F.ROWS, F.MAIN, F.FIXED, F.ROOTS, bytes.len });
        return;
    }
    return error.UsagePoseidonRowFixture;
}
