//! The single typed OP-P2 local receipt encoding authority. Integers are exact
//! u64s, external IDs are eight injectively encoded raw u32s, roots are nine
//! canonical M31s, and OM31 fields are eight canonical M31s. Every variable
//! vector has an explicit length. Writers must preserve these typed contracts.
const std = @import("std");
const Frame = @import("../word16_global_execution/services/gkr_local/frame.zig");
const MAX_INSTANCES = @import("../word16_global_execution/services/gkr_local/receipt.zig").MAX_INSTANCES;
pub const RECEIPT_TAG: u32 = 0x4f505232;
pub const VERSION: u32 = 1;
fn vector(writer: anytype, values: anytype) !void {
    writer.integer(values.len);
    for (values) |value| try writer.field(value);
}
pub fn emit(scope: anytype, instances: []const Frame.Instance, proof: anytype, marginals: anytype, writer: anytype) !void {
    if (instances.len == 0 or instances.len > MAX_INSTANCES or marginals.len != instances.len or proof.output_claims_by_instance.len != instances.len or proof.layer_masks_by_instance.len != instances.len or proof.sumcheck_proofs.len > 30) return error.LocalGkrReceiptShape;
    writer.tag(RECEIPT_TAG);
    writer.tag(VERSION);
    writer.tag(if (Frame.v3Instances(instances)) 3 else 1);
    writer.tag(8); // Secure field coordinates.
    writer.tag(9); // Internal root/digest coordinates.
    writer.rawDigest(scope.statement);
    writer.root(scope.fixed);
    writer.root(scope.main);
    writer.integer(scope.ordinal);
    writer.integer(instances.len);
    for (instances) |instance| {
        for (Frame.originWords(instance.origin)) |word| writer.integer(word);
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
