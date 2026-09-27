//! Public terminal fetch in the v5 program relation. This is arithmetic over
//! a native public statement, not independent proof authority. A block receiver
//! may admit it only after fresh native verification under pinned public data.
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const public = @import("../air/public_data.zig");
const decode = @import("../air/program/decode.zig");
const relation = @import("../air/lang/relation.zig");
const universal = @import("../recursion/air/universal_challenges.zig");

pub const Claim = struct { sum: Q, fetch_count: u64 };

/// Each unretired completion consumes one ROM word even though it has no
/// retired opcode row. The global table supplies its opposite relation term.
pub fn deriveFromPinnedNativePublic(
    profile: decode.ExecutionProfile,
    data: *const public.Blake3PublicData,
    relations: *const universal.UniversalRelations,
) !Claim {
    try data.validate();
    const completion = data.completion orelse return error.MissingCompletion;
    switch (completion.kind) {
        .halt_flag => return .{ .sum = Q.zero(), .fetch_count = 0 },
        .unretired_self_loop, .unretired_program_fetch => {},
    }
    const values = try decode.decodeProgramWordForProfile(profile, completion.value);
    var tuple: [5]M = undefined;
    tuple[0] = M.fromCanonical(completion.address);
    for (values, 0..) |value, i| {
        if (value >= core.fields.m31.Modulus) return error.NonCanonicalProgramField;
        tuple[i + 1] = M.fromCanonical(value);
    }
    const denominator = try relations.get(relation.Domain.program_access).combineBase(&tuple);
    // The public boundary consumes the program tuple, matching the native
    // public LogUp term. The global fixed table supplies the positive term.
    return .{ .sum = Q.zero().sub(try denominator.inv()), .fetch_count = 1 };
}
