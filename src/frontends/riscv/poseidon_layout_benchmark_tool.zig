//! Package-root executable boundary for the isolated H-010 benchmark.

pub fn main() void {
    @import("air/lang/poseidon_layout_benchmark_command.zig").main();
}
