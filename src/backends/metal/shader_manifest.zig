const authority = @import("shaders/manifest.zig");

pub const core_aot = @import("core_aot.zig");
pub const abi_contract = @import("shaders/abi_contract.zig");
pub const build_contract = @import("shaders/build_contract.zig");

pub const core_shader_abi = authority.core_shader_abi;
pub const CompileProfile = authority.CompileProfile;
pub const compile_profile = authority.compile_profile;
pub const Unit = authority.Unit;
pub const Export = authority.Export;
pub const exports = authority.exports;
pub const native_exports = authority.native_exports;
pub const native_amalgamated_source = authority.native_amalgamated_source;
pub const nativeAmalgamatedSourceDigest = authority.nativeAmalgamatedSourceDigest;
pub const amalgamated_source = authority.amalgamated_source;
pub const amalgamatedSourceDigest = authority.amalgamatedSourceDigest;

test {
    _ = @import("shaders/runtime_initialization_contract_test.zig");
}

test {
    _ = authority;
}
