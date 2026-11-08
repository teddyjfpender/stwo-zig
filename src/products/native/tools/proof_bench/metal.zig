const stwo = @import("stwo");
const runner = @import("native_proof_runner");

pub fn main() !void {
    return runner.main(stwo.backends.metal.MetalProverEngine, .metal_hybrid);
}
