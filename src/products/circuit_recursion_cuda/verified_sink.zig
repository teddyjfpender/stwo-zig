//! Borrow the verified resident Cairo proof for one recursive leaf wrap.
//! The capture is consumed in-process while its authenticated paths are live.
const std = @import("std");
const cairo_app = @import("cairo_cuda_app");
const circuit_app = @import("circuit_recursion_app");
const circuit_cpu = @import("stwo_circuit_cpu_integration");

pub const Context = struct {
    allocator: std.mem.Allocator,
    request: circuit_app.LeafWrapRequest,
    output_path: []const u8,
    delivered: bool = false,
    wrap_ns: u64 = 0,

    pub fn sink(self: *Context) cairo_app.VerifiedLeafSink {
        return .{ .context = self, .receive = receive };
    }

    fn receive(
        context: *anyopaque,
        prepared: *const @import("stwo_cairo_cuda_integration").canonical_source.Prepared,
        decoded: *const @import("stwo_cairo_cuda_integration").canonical_verify.Decoded,
        capture: *const @import("stwo_cairo_frontend").witness.resident_verifier.ProofCapture,
        interaction_pow: u64,
    ) anyerror!void {
        const self: *Context = @ptrCast(@alignCast(context));
        if (self.delivered) return error.DuplicateVerifiedLeaf;
        const verified = circuit_cpu.recursion.leaf_wrap.VerifiedCairoLeaf{
            .proof = &decoded.proof,
            .composition = &prepared.composition,
            .claimed_sums = decoded.claimed_sums,
            .interaction_pow = interaction_pow,
            .channel_salt = prepared.protocol.channel_salt,
            .preprocessed_variant = prepared.variant,
            .capture = capture,
        };
        var timer = try std.time.Timer.start();
        var leaf = try circuit_app.leafWrapVerified(self.allocator, self.request, verified, &prepared.input);
        defer leaf.deinit();
        try circuit_app.writeLeafProof(&leaf, self.output_path);
        self.wrap_ns = timer.read();
        self.delivered = true;
    }
};

test "verified leaf sink has the Cairo CUDA callback contract" {
    var context = Context{
        .allocator = std.testing.allocator,
        .request = undefined,
        .output_path = "unused",
    };
    const binding: cairo_app.VerifiedLeafSink = context.sink();
    try std.testing.expect(binding.context == @as(*anyopaque, @ptrCast(&context)));
}
