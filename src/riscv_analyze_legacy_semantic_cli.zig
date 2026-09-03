//! Package-root facade for the bounded Revm-42 `analyze_legacy` observer.

pub fn main() !void {
    return @import("tools/riscv/analyze_legacy_semantics/main.zig").main();
}
