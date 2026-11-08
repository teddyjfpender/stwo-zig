const stwo = @import("stwo");
const runner = @import("native_proof_runner");

pub fn main() !void {
    return runner.main(stwo.examples.wide_fibonacci.CpuProverEngine, .cpu_native);
}
