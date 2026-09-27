//! Proposed block-v4 native key split. This is an identity/admission contract,
//! not a proof verifier or a reusable verification key. The current native
//! Tree0 contains plan-dependent columns and cannot satisfy this contract as a
//! reusable setup without a separately qualified, versioned AIR.
const std = @import("std");

pub const Digest = [32]u8;
pub const VERSION: u32 = 1;
const Hash = std.crypto.hash.Blake3;

/// All fields must be invariant for every instance that uses the template.
/// In particular, `fixed_root` must eventually come from a qualified AIR
/// whose fixed columns depend only on these invariant fields. This module
/// cannot certify that property and does not expose a proof-acceptance API.
pub const Template = struct {
    air_abi: Digest,
    pcs_config: Digest,
    geometry: Digest,
    fixed_root: Digest,

    pub fn identity(self: Template) !Digest {
        try self.validate();
        var hash = Hash.init(.{});
        hash.update("stwo.riscv.block-v4.native-template.v1\x00");
        mixU32(&hash, VERSION);
        hash.update(&self.air_abi);
        hash.update(&self.pcs_config);
        hash.update(&self.geometry);
        hash.update(&self.fixed_root);
        return finish(&hash);
    }

    pub fn validate(self: Template) !void {
        if (empty(self.air_abi) or empty(self.pcs_config) or empty(self.geometry) or
            empty(self.fixed_root)) return error.MissingTemplateAuthority;
    }
};

/// Exact per-segment claims. Every digest here must be derived from an
/// independently admitted job or fresh proof/closure, never copied from the
/// untrusted proof bundle into the expected policy.
pub const Instance = struct {
    template_id: Digest,
    job_id: Digest,
    source_seal: Digest,
    segment_index: u32,
    segment_count: u32,
    segment_statement: Digest,
    native_public: Digest,
    exact_plan: Digest,
    first_round_roster: Digest,
    global_closure: Digest,

    pub fn identity(self: Instance) !Digest {
        try self.validate();
        var hash = Hash.init(.{});
        hash.update("stwo.riscv.block-v4.native-instance.v1\x00");
        mixU32(&hash, VERSION);
        hash.update(&self.template_id);
        hash.update(&self.job_id);
        hash.update(&self.source_seal);
        mixU32(&hash, self.segment_index);
        mixU32(&hash, self.segment_count);
        hash.update(&self.segment_statement);
        hash.update(&self.native_public);
        hash.update(&self.exact_plan);
        hash.update(&self.first_round_roster);
        hash.update(&self.global_closure);
        return finish(&hash);
    }

    pub fn validate(self: Instance) !void {
        if (self.segment_count == 0 or self.segment_index >= self.segment_count)
            return error.InvalidInstanceOrdinal;
        if (empty(self.template_id) or empty(self.job_id) or empty(self.source_seal) or
            empty(self.segment_statement) or empty(self.native_public) or empty(self.exact_plan) or
            empty(self.first_round_roster) or empty(self.global_closure))
            return error.MissingInstanceAuthority;
    }
};

/// Values obtained by fresh proof verification. A caller must still verify the
/// native proof and each global relation closure before constructing this.
pub const FreshBinding = struct {
    template_id: Digest,
    instance_id: Digest,
    fixed_root: Digest,
    first_round_roster: Digest,
    global_closure: Digest,
};

/// Policy supplied independently of the proof bundle. The identities alone
/// do not establish proof validity or independence of the policy source.
pub const IndependentPins = struct {
    template_id: Digest,
    instance_id: Digest,
    job_id: Digest,
    source_seal: Digest,
    first_round_roster: Digest,
    global_closure: Digest,
};

/// Enforce exact instance binding after fresh verification and global closure.
/// This function intentionally returns no `CompleteBlock` or proof receipt.
pub fn validateBound(template: Template, instance: Instance, fresh: FreshBinding, pins: IndependentPins) !void {
    const template_id = try template.identity();
    const instance_id = try instance.identity();
    if (!same(template_id, instance.template_id) or !same(template_id, pins.template_id) or
        !same(template_id, fresh.template_id) or !same(template.fixed_root, fresh.fixed_root))
        return error.TemplateBindingMismatch;
    if (!same(instance_id, pins.instance_id) or !same(instance_id, fresh.instance_id) or
        !same(instance.job_id, pins.job_id) or !same(instance.source_seal, pins.source_seal) or
        !same(instance.first_round_roster, pins.first_round_roster) or
        !same(instance.first_round_roster, fresh.first_round_roster) or
        !same(instance.global_closure, pins.global_closure) or
        !same(instance.global_closure, fresh.global_closure))
        return error.InstanceBindingMismatch;
}

fn empty(value: Digest) bool {
    const zero: Digest = @splat(0);
    return std.mem.eql(u8, &value, &zero);
}
fn same(left: Digest, right: Digest) bool {
    return std.mem.eql(u8, &left, &right);
}
fn mixU32(hash: *Hash, value: u32) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    hash.update(&bytes);
}
fn finish(hash: *Hash) Digest {
    var result: Digest = undefined;
    hash.final(&result);
    return result;
}
