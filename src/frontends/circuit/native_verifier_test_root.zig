//! Focused tests of the native-protocol in-circuit verifier
//! (`native_verifier/`), including the prover-backed end-to-end test. Run
//! with `zig build native-verifier-test --build-file src/frontends/circuit/build.zig`.

test {
    _ = @import("native_verifier/mod.zig");
}
