//! M4 diet stream: outer LogUp-GKR cost prototype (measurement only; no
//! production route). Separate root because test-riscv64-gkr-circuit does not
//! compile on bcd401ce4 (om31_evaluation_test / om31_main_only_test).
test {
    _ = @import("logup_gkr/outer_gkr_diet_test.zig");
}
