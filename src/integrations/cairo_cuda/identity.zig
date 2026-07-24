//! Canonical identities for the development-only Cairo proof-program emitter.

const std = @import("std");
const ir = @import("stwo_backend_contracts").proof_program;
const compact = @import("../../frontends/cairo/compact_verifier_interchange.zig");
const composition = @import("../../frontends/cairo/witness/composition_bundle.zig");
const semantic_pack = @import("../../frontends/cairo/witness/semantic_pack.zig");

pub const PackIdentity = struct {
    provenance: semantic_pack.Provenance,
    manifest: ir.Digest,
    composition_projection: ir.Digest,
    composition: ir.Digest,
    witness_programs: ir.Digest,
    multiplicity_feeds: ir.Digest,
    relation_templates: ir.Digest,
    fixed_tables: ir.Digest,
    preprocessed_coefficients: ir.Digest,
    verifier_max_log_degree_bound: u32,
    composition_plan_hash: u64,

    pub fn fromLoaded(pack: *const semantic_pack.Loaded) PackIdentity {
        return .{
            .provenance = pack.provenance,
            .manifest = pack.measurements.manifest.sha256,
            .composition_projection = pack.measurements.composition_projection_manifest.sha256,
            .composition = pack.measurements.composition.sha256,
            .witness_programs = pack.measurements.witness_programs.sha256,
            .multiplicity_feeds = pack.measurements.multiplicity_feeds.sha256,
            .relation_templates = pack.measurements.relation_templates.sha256,
            .fixed_tables = pack.measurements.fixed_tables.sha256,
            .preprocessed_coefficients = pack.measurements.preprocessed_coefficients.sha256,
            .verifier_max_log_degree_bound = pack.verifier_max_log_degree_bound,
            .composition_plan_hash = pack.composition.plan_hash,
        };
    }

    pub fn digest(self: PackIdentity) ir.Digest {
        var hash = canonicalHasher("stwo-zig/cairo/development-semantic-pack/v1");
        hashInt(&hash, u8, @intFromEnum(self.provenance));
        inline for (.{
            self.manifest,
            self.composition_projection,
            self.composition,
            self.witness_programs,
            self.multiplicity_feeds,
            self.relation_templates,
            self.fixed_tables,
            self.preprocessed_coefficients,
        }) |artifact_digest| hash.update(&artifact_digest);
        hashInt(&hash, u32, self.verifier_max_log_degree_bound);
        hashInt(&hash, u64, self.composition_plan_hash);
        return finish(&hash);
    }
};

pub fn statementDigest(encoded: []const u8) ir.Digest {
    var hash = canonicalHasher("stwo-zig/cairo/compact-statement/v1");
    hashBytes(&hash, encoded);
    return finish(&hash);
}

pub fn protocolDigest(protocol: compact.CompactProtocolV1) !ir.Digest {
    const encoded = try protocol.encode();
    var hash = canonicalHasher("stwo-zig/cairo/compact-protocol/v1");
    hashBytes(&hash, &encoded);
    return finish(&hash);
}

pub fn componentProgramDigest(
    pack_digest: ir.Digest,
    component: composition.Component,
) ir.Digest {
    var hash = canonicalHasher("stwo-zig/cairo/component-program/v1");
    hash.update(&pack_digest);
    hashBytes(&hash, component.label);
    inline for (.{
        component.instance,
        component.trace_log_size,
        component.evaluation_log_size,
        component.n_constraints,
        component.random_coefficient_offset,
    }) |value| hashInt(&hash, u32, value);
    hashInt(&hash, u64, component.trace_spans.len);
    for (component.trace_spans) |span| {
        hashInt(&hash, u32, span.tree);
        hashInt(&hash, u32, span.start);
        hashInt(&hash, u32, span.end);
    }
    hashU32Slice(&hash, component.preprocessed_indices);
    hashU32Slice(&hash, component.denominator_inverses);
    hashInt(&hash, u64, component.ext_sources.len);
    for (component.ext_sources) |source| hashExtSource(&hash, source);
    hashInt(&hash, u64, component.parts.len);
    for (component.parts) |part| {
        hashInt(&hash, u32, part.rc_base);
        hashInt(&hash, u64, part.semantic_hash);
        hashProgram(&hash, part.program);
    }
    return finish(&hash);
}

fn hashProgram(hash: *std.crypto.hash.sha2.Sha256, program: anytype) void {
    const header = program.header;
    inline for (.{
        header.flags,
        header.n_interactions,
        header.n_base_params,
        header.n_ext_params,
        header.n_constraints,
        header.max_base_regs,
        header.max_ext_regs,
        header.domain_log_size,
    }) |value| hashInt(hash, u32, value);
    hashInt(hash, u64, header.semantic_hash);
    hashInt(hash, u64, header.capability_bits);
    hashU32Slice(hash, program.base_consts);
    hashInt(hash, u64, program.ext_consts.len);
    for (program.ext_consts) |value| for (value) |limb| hashInt(hash, u32, limb);
    hashInt(hash, u64, program.base_insts.len);
    for (program.base_insts) |inst| {
        hashInt(hash, u8, @intFromEnum(inst.op));
        hashInt(hash, u8, inst.interaction);
        hashInt(hash, u16, inst.dst);
        hashInt(hash, u32, inst.a);
        hashInt(hash, u32, inst.b);
        hashInt(hash, i32, inst.imm);
    }
    hashInt(hash, u64, program.ext_insts.len);
    for (program.ext_insts) |inst| {
        hashInt(hash, u8, @intFromEnum(inst.op));
        hashInt(hash, u16, inst.dst);
        inline for (.{ inst.a, inst.b, inst.c, inst.d }) |value| hashInt(hash, u32, value);
    }
    hashU32Slice(hash, program.constraint_roots);
}

fn hashExtSource(hash: *std.crypto.hash.sha2.Sha256, source: composition.ExtSource) void {
    hashInt(hash, u8, @intFromEnum(source));
    switch (source) {
        .constant => |value| for (value) |limb| hashInt(hash, u32, limb),
        .lookup_z, .claimed_sum_scaled => {},
        .lookup_alpha_power => |power| hashInt(hash, u32, power),
        .lookup_alpha_power_scaled => |scaled| {
            hashInt(hash, u32, scaled.power);
            hashInt(hash, u32, scaled.scale);
        },
    }
}

fn canonicalHasher(domain: []const u8) std.crypto.hash.sha2.Sha256 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hashBytes(&hash, domain);
    return hash;
}

fn hashBytes(hash: *std.crypto.hash.sha2.Sha256, bytes: []const u8) void {
    hashInt(hash, u64, bytes.len);
    hash.update(bytes);
}

fn hashU32Slice(hash: *std.crypto.hash.sha2.Sha256, values: []const u32) void {
    hashInt(hash, u64, values.len);
    for (values) |value| hashInt(hash, u32, value);
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

fn finish(hash: *std.crypto.hash.sha2.Sha256) ir.Digest {
    var digest: ir.Digest = undefined;
    hash.final(&digest);
    return digest;
}
