//! Named protocol modules shared by every assembled product.

const std = @import("std");

pub const ProtocolModules = struct {
    core: *std.Build.Module,
    backend_contracts: *std.Build.Module,
    prover_api: *std.Build.Module,
    prover: *std.Build.Module,

    pub fn addImports(self: ProtocolModules, module: *std.Build.Module) void {
        module.addImport("stwo_core", self.core);
        module.addImport("stwo_backend_contracts", self.backend_contracts);
        module.addImport("stwo_prover_api", self.prover_api);
        module.addImport("stwo_prover_engine", self.prover);
    }
};
