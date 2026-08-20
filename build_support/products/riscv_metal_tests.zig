//! Product-owned Metal acceptance lanes and isolated shell tests.

const std = @import("std");
const metal = @import("../backends/metal.zig");
const metal_aot = @import("../backends/metal_aot.zig");
const graph = @import("../graph/modules.zig");
const modules = @import("riscv_metal_modules.zig");

/// Fresh-process product acceptance for the exact extension profile. The
/// deterministic eight-call vector keeps every backend-owned proof operation
/// above the resident threshold; any CPU fallback prevents publication and
/// fails this step. Proving and verification are separate process invocations.
pub fn addGuestPoseidon2AotLane(
    context: modules.Context,
    product: graph.Product,
    aot_bundle: metal_aot.ExternalBundle,
    executable: *std.Build.Step.Compile,
) void {
    _ = product;
    const b = context.b;
    const guest_root = b.path("vectors/riscv_guests/poseidon2_m31_permute_v1");
    const guest_build = b.addSystemCommand(&.{
        "cargo",
        "build",
        "--release",
        "--features",
        "precompile",
    });
    guest_build.setCwd(guest_root);
    guest_build.setEnvironmentVariable("CARGO_TARGET_DIR", "target-precompile");

    const input_bytes = poseidon2Input(b.allocator, 8) catch |err|
        std.debug.panic("cannot construct guest Poseidon2 input: {s}", .{@errorName(err)});
    const generated = b.addWriteFiles();
    const input = generated.add("guest-poseidon2-eight-calls.bin", input_bytes);

    const prove = b.addRunArtifact(executable);
    prove.setCwd(b.path("."));
    prove.setEnvironmentVariable(
        "STWO_RISCV_METAL_AOT_BUNDLE",
        aot_bundle.absolute_path,
    );
    prove.addArgs(&.{
        "guest-poseidon2-prove",
        "--elf",
        "vectors/riscv_guests/poseidon2_m31_permute_v1/target-precompile/" ++
            "riscv32im-unknown-none-elf/release/poseidon2_m31_permute_v1",
        "--input",
    });
    prove.addFileArg(input);
    prove.addArgs(&.{
        "--backend",
        "metal",
        "--max-steps",
        "900000",
        "--protocol",
        "functional",
        "--output",
    });
    const artifact = prove.addOutputFileArg("guest-poseidon2-proof.stw");
    prove.addArg("--report-out");
    _ = prove.addOutputFileArg("guest-poseidon2-proof-report.json");
    prove.step.dependOn(&guest_build.step);

    const verify = b.addRunArtifact(executable);
    verify.addArgs(&.{ "guest-poseidon2-verify", "--artifact" });
    verify.addFileArg(artifact);
    verify.addArgs(&.{ "--protocol", "functional" });
    b.step(
        "test-riscv-metal-guest-poseidon2-aot",
        "Prove and independently verify the exact guest Poseidon2 profile on authenticated Metal AOT",
    ).dependOn(&verify.step);
}

fn poseidon2Input(allocator: std.mem.Allocator, call_count: usize) ![]u8 {
    const lanes = 16;
    const modulus: u64 = 0x7fff_ffff;
    const words = try std.math.add(
        usize,
        1,
        try std.math.mul(usize, call_count, lanes),
    );
    const bytes = try allocator.alloc(u8, try std.math.mul(usize, words, @sizeOf(u32)));
    std.mem.writeInt(u32, bytes[0..4], @intCast(call_count), .little);
    var random_state: u64 = 0x6a09_e667_f3bc_c909;
    for (0..call_count) |call| {
        for (0..lanes) |lane| {
            const value: u32 = if (call == 0)
                @intCast(lane)
            else value: {
                random_state +%= 0x9e37_79b9_7f4a_7c15;
                var mixed = random_state;
                mixed = (mixed ^ (mixed >> 30)) *% 0xbf58_476d_1ce4_e5b9;
                mixed = (mixed ^ (mixed >> 27)) *% 0x94d0_49bb_1331_11eb;
                mixed ^= mixed >> 31;
                break :value @intCast(mixed % modulus);
            };
            const word = 1 + call * lanes + lane;
            std.mem.writeInt(u32, bytes[4 * word ..][0..4], value, .little);
        }
    }
    return bytes;
}

/// Run each shell file as its own test root so Zig discovers its declarations
/// and each binary imports only the module graph it actually exercises.
pub fn addShellTests(
    context: modules.Context,
    product: graph.Product,
    aot_bundle: metal_aot.ExternalBundle,
    test_step: *std.Build.Step,
) void {
    const b = context.b;
    const identity_product = modules.roleProduct(product, .@"test");

    const app = modules.rootModule(
        context,
        product,
        identity_product,
        "src/products/riscv_metal/app.zig",
        aot_bundle,
    );
    const app_tests = b.addTest(.{ .root_module = app });
    metal.linkRuntime(b, app_tests);
    const run_app_tests = b.addRunArtifact(app_tests);
    run_app_tests.setEnvironmentVariable(
        "STWO_RISCV_METAL_AOT_BUNDLE",
        aot_bundle.absolute_path,
    );
    test_step.dependOn(&run_app_tests.step);

    const cli = modules.binding(context, product).leafModule(
        "src/products/riscv_metal/cli.zig",
    );
    cli.addImport("riscv_shared_cli", modules.binding(context, product).leafModule(
        "src/products/riscv_shared/cli.zig",
    ));
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = cli })).step);

    const registry = modules.binding(context, product).leafModule(
        "src/products/riscv_metal/registry.zig",
    );
    registry.addImport("riscv_capabilities", modules.capabilitiesModule(context, product));
    registry.addImport("riscv_shared_registry", modules.binding(context, product).leafModule(
        "src/products/riscv_shared/registry.zig",
    ));
    registry.addOptions(
        "product_identity",
        modules.productIdentityOptions(context, identity_product, aot_bundle),
    );
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = registry })).step);
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{
        .root_module = modules.capabilitiesModule(context, product),
    })).step);
}
