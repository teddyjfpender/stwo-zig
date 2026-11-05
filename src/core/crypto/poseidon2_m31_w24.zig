// SPDX-License-Identifier: MIT
// Copyright (c) 2022 The Plonky3 Authors
//! Width24 Poseidon2-M31, pinned to the official Plonky3 permutation.
//! New-profile substrate only; existing hash/channel families are unchanged.
const std = @import("std");
const M31 = @import("../fields/m31.zig").M31;
pub const parameters = @import("poseidon2_m31_w24_constants.zig");
pub const WIDTH: usize = 24;
pub const FULL_ROUNDS: usize = 8;
pub const PARTIAL_ROUNDS: usize = 22;
pub const State = [WIDTH]M31;
pub const PARAMETER_DOMAIN = "stwo/poseidon2/m31/p3-w24-rf8-rp22-x5-mds4-diag/v1";

/// Ops exposes fallible constant(u32), add, sub and mul. Circuit adapters must
/// enforce M31 input ports: x^5 over an unconstrained extension field is not
/// this permutation. Native M31 arithmetic satisfies the field contract.
pub fn permuteFor(comptime Scalar: type, ops: anytype, state: *[WIDTH]Scalar) !void {
    try externalFor(Scalar,ops,state);
    for(parameters.EXTERNAL_INITIAL) |round| try fullFor(Scalar,ops,state,round);
    for(parameters.INTERNAL) |constant| {
        state[0] = try sboxFor(Scalar,ops,try ops.add(state[0],try ops.constant(constant)));
        try internalFor(Scalar,ops,state);
    }
    for(parameters.EXTERNAL_FINAL) |round| try fullFor(Scalar,ops,state,round);
}
fn sboxFor(comptime Scalar:type,ops:anytype,value:Scalar)!Scalar {
    const square=try ops.mul(value,value);
    return ops.mul(try ops.mul(square,square),value);
}
fn fullFor(comptime Scalar:type,ops:anytype,state:*[WIDTH]Scalar,round:[WIDTH]u32)!void {
    for(state,round) |*value,constant| value.*=try sboxFor(Scalar,ops,try ops.add(value.*,try ops.constant(constant)));
    try externalFor(Scalar,ops,state);
}
pub fn externalFor(comptime Scalar:type,ops:anytype,state:*[WIDTH]Scalar)!void {
    // Pinned P3 MDSMat4: [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]].
    for(0..WIDTH/4) |group| {
        const i=4*group;
        const a=state[i];const b=state[i+1];const c=state[i+2];const d=state[i+3];
        const ab=try ops.add(a,b);const cd=try ops.add(c,d);
        const all=try ops.add(ab,cd);const all_b=try ops.add(all,b);const all_d=try ops.add(all,d);
        state[i+3]=try ops.add(all_d,try ops.add(a,a));
        state[i+1]=try ops.add(all_b,try ops.add(c,c));
        state[i]=try ops.add(all_b,ab);state[i+2]=try ops.add(all_d,cd);
    }
    for(0..4) |lane| {
        var sum=state[lane];
        for(1..WIDTH/4) |group| sum=try ops.add(sum,state[4*group+lane]);
        for(0..WIDTH/4) |group| state[4*group+lane]=try ops.add(state[4*group+lane],sum);
    }
}
pub fn internalFor(comptime Scalar:type,ops:anytype,state:*[WIDTH]Scalar)!void {
    var part=state[1];for(2..WIDTH) |i| part=try ops.add(part,state[i]);
    const all=try ops.add(part,state[0]);
    state[0]=try ops.sub(part,state[0]);
    state[1]=try ops.add(all,state[1]);
    state[2]=try ops.add(all,try ops.add(state[2],state[2]));
    for(3..WIDTH) |i| state[i]=try ops.add(all,try ops.mul(state[i],try ops.constant(parameters.INTERNAL_DIAGONAL[i])));
}
const NativeOps=struct {
    pub fn constant(_: @This(),value:u32)!M31{return M31.fromCanonical(value);}
    pub fn add(_: @This(),a:M31,b:M31)!M31{return a.add(b);}
    pub fn sub(_: @This(),a:M31,b:M31)!M31{return a.sub(b);}
    pub fn mul(_: @This(),a:M31,b:M31)!M31{return a.mul(b);}
};
pub fn permute(state:*State)void {permuteFor(M31,NativeOps{},state) catch unreachable;}
/// Numeric parameters AND the matrix/framing algorithm ID enter profile IDs.
pub fn parameterIdentity()[32]u8 {
    var hash=std.crypto.hash.sha2.Sha256.init(.{});hash.update(PARAMETER_DOMAIN);
    var bytes:[4]u8=undefined;
    for([_]u32{WIDTH,FULL_ROUNDS,PARTIAL_ROUNDS,5}++parameters.INTERNAL_DIAGONAL) |word| {
        std.mem.writeInt(u32,&bytes,word,.little);hash.update(&bytes);
    }
    for(parameters.EXTERNAL_INITIAL++parameters.EXTERNAL_FINAL) |round|for(round) |word| {
        std.mem.writeInt(u32,&bytes,word,.little);hash.update(&bytes);
    };
    for(parameters.INTERNAL) |word|{std.mem.writeInt(u32,&bytes,word,.little);hash.update(&bytes);}
    var out:[32]u8=undefined;hash.final(&out);return out;
}
test "Poseidon2 M31 width24 matches pinned Plonky3 known answer" {
    var state:State=undefined;for(&state,0..) |*value,i|value.*=M31.fromCanonical(@intCast(i));
    permute(&state);
    for(state,parameters.KAT_0_TO_23) |value,expected|try std.testing.expectEqual(expected,value.v);
}
test "Poseidon2 width24 independent dense-matrix vectors and parameter identity" {
    for(@import("poseidon2_m31_w24_vectors.zig").VECTORS) |vector|{
        var state:State=undefined;for(&state,vector.input) |*value,word|value.*=M31.fromCanonical(word);
        permute(&state);
        for(state,vector.output) |value,expected|try std.testing.expectEqual(expected,value.v);
    }
    const expected:[32]u8=.{0xd2,0x57,0x1a,0x7f,0x49,0x6f,0x01,0x40,0xe9,0x67,0xe4,0xbf,0xc5,0xec,0xcb,0xd6,0x24,0xc9,0x51,0xfc,0xdf,0xee,0x7d,0xfc,0xe1,0xc3,0xba,0xe3,0x93,0x31,0x29,0x3e};
    try std.testing.expectEqualSlices(u8,&expected,&parameterIdentity());
}
