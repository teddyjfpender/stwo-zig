const std = @import("std");
const core = @import("stwo_core");
const generic = @import("stwo_prover");
const compatibility = @import("stwo");

pub fn main() !void {
    const M31 = core.fields.m31.M31;
    const sum = M31.fromCanonical(13).add(M31.fromCanonical(29));
    if (!sum.eql(M31.fromCanonical(42))) return error.CoreSmokeFailed;
    if (!@hasDecl(generic, "prover") or !@hasDecl(generic, "backend"))
        return error.ProverSurfaceMissing;
    if (!@hasDecl(compatibility, "core") or !@hasDecl(compatibility, "prover"))
        return error.CompatibilitySurfaceMissing;
    const wire = compatibility.recursion_wire;
    const cairo = compatibility.frontends.cairo;
    comptime {
        if (compatibility.core != core or compatibility.prover != generic.prover or compatibility.backend != generic.backend)
            @compileError("public protocol module identity drifted");
        _ = compatibility.prover_api;
        _ = compatibility.proof_wire;
        if (wire.cairo_serialize != cairo.proof.cairo_serde.felt_json)
            @compileError("recursion wire duplicated the Cairo felt authority");
        if (wire.registry.ProverParameters != cairo.proving.leaf_lane.ProverParameters)
            @compileError("recursion wire duplicated the Cairo parameter authority");
    }
    const allocator = std.heap.page_allocator;
    const felts = try wire.cairo_serialize.parseFeltJson(allocator, "[\"0x0\",\"0xffffffffffffffff\"]");
    defer allocator.free(felts);
    if (felts.len != 2 or felts[0] != 0 or felts[1] != std.math.maxInt(u64))
        return error.RecursionWireSmokeFailed;
    if (wire.cairo_serialize.parseFeltJson(allocator, "[\"0x00\"]")) |invalid| {
        allocator.free(invalid);
        return error.NonCanonicalWireAccepted;
    } else |err| if (err != error.NonCanonicalFelt) return err;
    try std.fs.File.stdout().writeAll("downstream package smoke: PASS\n");
}
