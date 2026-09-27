//! Exact expected-public authority hash calls shared by native custody and verification.
const std = @import("std");
const core = @import("stwo_core");
const m31 = core.fields.m31;
const M31 = m31.M31;
const channel = @import("poseidon2_channel.zig");
const Digest = channel.Digest;
const statement_v1 = @import("../air/statement_geometry.zig");
const public_data_v2 = @import("../air/public_data_v2.zig");
const projection = @import("../air/statement_v2_public_projection.zig");
const preimage = @import("../air/statement_v2_authority_preimage.zig");
const poseidon2 = @import("../air/memory_commitment/poseidon2.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_call.zig");
pub const Error = projection.Error || preimage.ValidationError || error{ AliasedDestination, PoseidonCallCountMismatch };

/// Receipt-free expected hash program from public statement and admitted native
/// geometry. Both native custody and detached verification use this one emitter.
pub fn authorityHashCallCount(component_count: usize, infra_count: usize) Error!usize {
    return channel.canonicalWordPermutationCount(try preimage.wordCount(component_count, infra_count));
}

pub fn appendExpectedAuthorityHashCalls(
    destination: []poseidon2_air.Call,
    data: *const public_data_v2.PublicDataV2,
    component_descs: []const statement_v1.FamilyComponentDesc,
    infra_descs: []const statement_v1.InfraComponentDesc,
) Error!Digest {
    const destination_bytes = std.mem.sliceAsBytes(destination);
    inline for (.{ std.mem.asBytes(data), std.mem.sliceAsBytes(data.words()), std.mem.sliceAsBytes(component_descs), std.mem.sliceAsBytes(infra_descs) }) |input|
        if (overlap(destination_bytes, input)) return error.AliasedDestination;
    const count = try authorityHashCallCount(component_descs.len, infra_descs.len);
    if (destination.len != count) return error.PoseidonCallCountMismatch;
    const core_public = try projection.canonicalCorePublicData(data);
    const input = preimage.Input{
        .initial_pc = core_public.initial_pc,
        .final_pc = core_public.final_pc,
        .cycle_count = core_public.clock,
        .wire_id = data.wireId(),
        .component_descs = component_descs,
        .infra_descs = infra_descs,
    };
    try input.validate();
    var recorder = AuthorityHashCallRecorder.init(destination);
    preimage.emit(&recorder, input);
    const output = recorder.finalize();
    std.debug.assert(recorder.call_at == destination.len);
    return output;
}

pub const AuthorityHashCallRecorder = struct {
    state: [poseidon2_air.WIDTH]M31,
    filled: usize = 0,
    calls: []poseidon2_air.Call,
    call_at: usize = 0,

    fn init(calls: []poseidon2_air.Call) AuthorityHashCallRecorder {
        const state = channel.canonical_word_sponge.initialState(M31, M31.zero(), M31.fromCanonical(preimage.DOMAIN));
        return .{ .state = state, .calls = calls };
    }

    fn canonical(self: *AuthorityHashCallRecorder, value: u32) void {
        std.debug.assert(value < m31.Modulus);
        channel.canonical_word_sponge.absorb(self, M31.fromCanonical(value));
    }

    pub fn word(self: *AuthorityHashCallRecorder, _: preimage.Source, value: u32) void {
        self.canonical(value);
    }

    pub fn permute(self: *AuthorityHashCallRecorder) void {
        std.debug.assert(self.call_at < self.calls.len);
        var input: [poseidon2_air.WIDTH]u32 = undefined;
        for (&input, self.state) |*destination, field_word|
            destination.* = field_word.toU32();
        self.calls[self.call_at] = .{
            .input = input,
            .wide = false,
            .io = true,
            .narrow_output = null,
        };
        self.call_at += 1;
        poseidon2.permute(&self.state);
        self.filled = 0;
    }

    fn finalize(self: *AuthorityHashCallRecorder) Digest {
        channel.canonical_word_sponge.finish(self, M31.one());
        var result: Digest = undefined;
        for (&result, self.state[0..channel.RATE]) |*destination, field_word|
            destination.* = field_word.toU32();
        return result;
    }
};

pub fn overlap(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = left_start + left.len;
    const right_end = right_start + right.len;
    return left_start < right_end and right_start < left_end;
}
