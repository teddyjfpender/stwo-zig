const std = @import("std");
const contract = @import("block_v4_native_template_contract_v1.zig");
const Digest = contract.Digest;

fn digest(byte: u8) Digest {
    return @splat(byte);
}
fn template() contract.Template {
    return .{
        .air_abi = digest(1),
        .pcs_config = digest(2),
        .geometry = digest(3),
        .fixed_root = digest(4),
    };
}
fn instance(template_id: Digest, index: u32) contract.Instance {
    return .{
        .template_id = template_id,
        .job_id = digest(5),
        .source_seal = digest(6),
        .segment_index = index,
        .segment_count = 2,
        .segment_statement = digest(@intCast(7 + index)),
        .native_public = digest(@intCast(9 + index)),
        .exact_plan = digest(@intCast(11 + index)),
        .first_round_roster = digest(@intCast(13 + index)),
        .global_closure = digest(@intCast(15 + index)),
    };
}
fn binding(t: contract.Template, i: contract.Instance) !contract.FreshBinding {
    return .{
        .template_id = try t.identity(),
        .instance_id = try i.identity(),
        .fixed_root = t.fixed_root,
        .first_round_roster = i.first_round_roster,
        .global_closure = i.global_closure,
    };
}
fn pins(t: contract.Template, i: contract.Instance) !contract.IndependentPins {
    return .{
        .template_id = try t.identity(),
        .instance_id = try i.identity(),
        .job_id = i.job_id,
        .source_seal = i.source_seal,
        .first_round_roster = i.first_round_roster,
        .global_closure = i.global_closure,
    };
}

test "native template contract accepts two distinct instances only under their own pins" {
    const t = template();
    const one = instance(try t.identity(), 0);
    const two = instance(try t.identity(), 1);
    const one_id = try one.identity();
    const two_id = try two.identity();
    try std.testing.expect(!std.mem.eql(u8, &one_id, &two_id));
    try contract.validateBound(t, one, try binding(t, one), try pins(t, one));
    try contract.validateBound(t, two, try binding(t, two), try pins(t, two));
    try std.testing.expectError(error.InstanceBindingMismatch,
        contract.validateBound(t, one, try binding(t, two), try pins(t, one)));
    try std.testing.expectError(error.InstanceBindingMismatch,
        contract.validateBound(t, one, try binding(t, one), try pins(t, two)));
}

test "native template contract rejects missing or swapped dynamic authority" {
    const t = template();
    const original = instance(try t.identity(), 0);
    const fresh = try binding(t, original);
    const trusted = try pins(t, original);

    var changed = original;
    changed.source_seal = digest(20);
    try std.testing.expectError(error.InstanceBindingMismatch,
        contract.validateBound(t, changed, fresh, trusted));
    changed = original;
    changed.exact_plan = digest(21);
    try std.testing.expectError(error.InstanceBindingMismatch,
        contract.validateBound(t, changed, fresh, trusted));
    changed = original;
    changed.native_public = digest(22);
    try std.testing.expectError(error.InstanceBindingMismatch,
        contract.validateBound(t, changed, fresh, trusted));
    changed = original;
    changed.source_seal = digest(0);
    try std.testing.expectError(error.MissingInstanceAuthority,
        contract.validateBound(t, changed, fresh, trusted));
    changed = original;
    changed.global_closure = digest(0);
    try std.testing.expectError(error.MissingInstanceAuthority,
        contract.validateBound(t, changed, fresh, trusted));
    changed = original;
    changed.segment_index = 2;
    try std.testing.expectError(error.InvalidInstanceOrdinal,
        contract.validateBound(t, changed, fresh, trusted));

    var forged = fresh;
    forged.first_round_roster = digest(23);
    try std.testing.expectError(error.InstanceBindingMismatch,
        contract.validateBound(t, original, forged, trusted));
    forged = fresh;
    forged.global_closure = digest(24);
    try std.testing.expectError(error.InstanceBindingMismatch,
        contract.validateBound(t, original, forged, trusted));
}

test "native template contract binds setup geometry config and fixed root" {
    const t = template();
    const i = instance(try t.identity(), 0);
    const fresh = try binding(t, i);
    const trusted = try pins(t, i);
    inline for (.{ "air_abi", "pcs_config", "geometry", "fixed_root" }) |field| {
        var changed = t;
        @field(changed, field) = digest(30);
        try std.testing.expectError(error.TemplateBindingMismatch,
            contract.validateBound(changed, i, fresh, trusted));
    }
    var absent = t;
    absent.fixed_root = digest(0);
    try std.testing.expectError(error.MissingTemplateAuthority,
        contract.validateBound(absent, i, fresh, trusted));
}
