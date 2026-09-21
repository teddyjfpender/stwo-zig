# Run from repository root. Metal requires the authenticated core AOT bundle.
STWO_SECP256K1_CSP_SAMPLES=10 zig build --build-file src/integrations/riscv_cpu/build.zig test-secp256k1-precompile-proof -Doptimize=ReleaseFast --summary all
STWO_SECP256K1_CSP_SAMPLES=10 zig build --build-file src/integrations/riscv_metal/build.zig test-secp256k1-precompile-proof -Doptimize=ReleaseFast -Dmetal-core-aot-bundle=/tmp/pr198-csp-clean-source-v1/zig-out/share/stwo-zig/metal/core --summary all
