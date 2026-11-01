//! Canonical stage-one local proof custody. The global manifest must mix this
//! digest AND its independently reconstructed scope after verifying the local
//! child transcript; no caller-supplied terminal marginal is authenticated here.
const std = @import("std");
const core = @import("stwo_core");
const O = core.fields.om31.OM31;
const Instance = @import("frame.zig").Instance;
const Proof = @import("stwo_prover_engine").lookups.gkr_verifier.ForField(O).GkrBatchProof;
pub const MAX_INSTANCES = 64;
pub const Scope = struct {
    statement: [32]u8,
    fixed: [32]u8,
    main: [32]u8,
    ordinal: u32,
};
const Writer = struct {
    hash: std.crypto.hash.blake2.Blake2s256 = .init(.{}),
    fields: usize = 0,
    fn bytes(self: *Writer, value: anytype) void {
        self.hash.update(value);
    }
    fn integer(self: *Writer, value: usize) void {
        var encoded: [8]u8 = undefined;
        std.mem.writeInt(u64, &encoded, @intCast(value), .little);
        self.hash.update(&encoded);
    }
    fn field(self: *Writer, value: O) !void {
        if (self.fields >= 1 << 20) return error.LocalGkrProofLimit;
        self.fields += 1;
        for (value.toM31Array()) |coordinate| {
            if (coordinate.v >= core.fields.m31.Modulus) return error.NoncanonicalLocalGkrCoordinate;
            var encoded: [4]u8 = undefined;
            std.mem.writeInt(u32, &encoded, coordinate.v, .little);
            self.hash.update(&encoded);
        }
    }
    fn vector(self: *Writer, values: []const O) !void {
        self.integer(values.len);
        for (values) |value| try self.field(value);
    }
};
fn vector(writer: anytype, values: anytype) !void {
    writer.integer(values.len);
    for (values) |value| try writer.field(value);
}
/// Shared framing visitor for native digest and constrained circuit digest.
/// Literal bytes and public shape integers are trusted; field coordinates are
/// emitted through writer.field, which must constrain canonical encodings.
pub fn emitCanonical(scope: anytype, instances: []const Instance, proof: anytype, marginals: anytype, writer: anytype) !void {
    if (instances.len == 0 or instances.len > MAX_INSTANCES or marginals.len != instances.len or proof.output_claims_by_instance.len != instances.len or proof.layer_masks_by_instance.len != instances.len or proof.sumcheck_proofs.len > 30) return error.LocalGkrReceiptShape;
    writer.bytes("RV64-SERVICES-LOCAL-GKR-OM31-V1");
    writer.bytes(&scope.statement);
    writer.bytes(&scope.fixed);
    writer.bytes(&scope.main);
    writer.integer(scope.ordinal);
    writer.integer(8); // Explicit field coordinate authority.
    writer.integer(instances.len);
    for (instances) |instance| {
        switch (instance.origin) {
            .core => |role| {
                writer.integer(0);
                writer.integer(@intFromEnum(role));
            },
            .bridge => |family| {
                writer.integer(1);
                writer.integer(@intFromEnum(family));
            },
        }
        writer.integer(instance.row_log);
        writer.integer(instance.terms);
        writer.integer(try instance.variables());
        writer.integer(instance.fixed_offset);
        writer.integer(instance.main_offset);
    }
    writer.integer(proof.sumcheck_proofs.len);
    for (proof.sumcheck_proofs) |sumcheck| {
        if (sumcheck.round_polys.len > 30) return error.LocalGkrReceiptShape;
        writer.integer(sumcheck.round_polys.len);
        for (sumcheck.round_polys) |polynomial| {
            if (polynomial.coeffsSlice().len > 4) return error.LocalGkrReceiptShape;
            try vector(writer, polynomial.coeffsSlice());
        }
    }
    for (proof.layer_masks_by_instance, instances) |masks, instance| {
        if (masks.len != try instance.variables()) return error.LocalGkrReceiptShape;
        writer.integer(masks.len);
        for (masks) |mask| {
            if (mask.columns.len != 2) return error.LocalGkrReceiptShape;
            writer.integer(mask.columns.len);
            for (mask.columns) |column| try vector(writer, &column);
        }
    }
    for (proof.output_claims_by_instance, marginals) |outputs, inputs| {
        if (outputs.len != 2 or inputs.len != 2) return error.LocalGkrReceiptShape;
        try vector(writer, outputs);
        try vector(writer, inputs);
    }
}

pub fn digest(scope: Scope, instances: []const Instance, proof: *const Proof, marginals: []const []const O) ![32]u8 {
    var writer = Writer{};
    try emitCanonical(scope, instances, proof, marginals, &writer);
    var out: [32]u8 = undefined;
    writer.hash.final(&out);
    return out;
}
