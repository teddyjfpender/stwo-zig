//! BUILD-only construction against actual caller-selected native modules.
//! No dependencies or protocol modules are reconstructed here. The caller owns
//! its module graph and supplies the package source root explicitly.
const std = @import("std");
const Module = std.Build.Module;

fn bind(component: *Module, name: []const u8, dependency: *Module) void {
    if (component.import_table.get(name)) |existing| {
        if (existing != dependency) @panic("Ethereum canonical module identity drift");
    } else component.addImport(name, dependency);
}
fn inherit(component: *Module, predecessor: *Module) void {
    for (predecessor.import_table.keys(), predecessor.import_table.values()) |name, dependency|
        bind(component, name, dependency);
}

/// Read the actual selected CPU's predecessors; never reconstruct their owners.
pub fn nativeCpuPredecessors(native: *Module) struct { frontend: *Module, backend: *Module } {
    const front = native.import_table.get("stwo_riscv_frontend") orelse @panic("selected CPU lacks frontend");
    const backend = native.import_table.get("stwo_cpu_backend") orelse @panic("selected CPU lacks backend");
    const core = native.import_table.get("stwo_core") orelse @panic("selected CPU lacks Core");
    if (front.import_table.get("stwo_core") != core or backend.import_table.get("stwo_core") != core) @panic("selected CPU predecessor Core drift");
    return .{ .frontend = front, .backend = backend };
}

pub fn frontend(b: *std.Build, source: std.Build.LazyPath, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, native: *Module) *Module {
    const result = b.createModule(.{ .root_source_file = source, .target = target, .optimize = optimize });
    bindFrontend(result, native);
    return result;
}

pub fn bindFrontend(result: *Module, native: *Module) void {
    inherit(result, native);
    bind(result, "stwo_riscv_frontend", native);
}

pub fn cpu(b: *std.Build, source: std.Build.LazyPath, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, front: *Module, native: *Module) *Module {
    const result = b.createModule(.{ .root_source_file = source, .target = target, .optimize = optimize });
    bindCpu(result, front, native);
    return result;
}

pub fn bindCpu(result: *Module, front: *Module, native: *Module) void {
    inherit(result, front);
    inherit(result, native);
    bind(result, "stwo_riscv_cpu_integration", native);
    bind(result, "ethereum_frontend_component", front);
}

pub fn cuda(b: *std.Build, source: std.Build.LazyPath, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, front: *Module, cpu_component: *Module, native: *Module) *Module {
    const result = b.createModule(.{ .root_source_file = source, .target = target, .optimize = optimize });
    bindCuda(result, front, cpu_component, native);
    return result;
}

pub fn bindCuda(result: *Module, front: *Module, cpu_component: *Module, native: *Module) void {
    inherit(result, front);
    inherit(result, cpu_component);
    inherit(result, native);
    bind(result, "stwo_riscv_cuda_integration", native);
    bind(result, "ethereum_frontend_component", front);
    bind(result, "ethereum_cpu_component", cpu_component);
}

pub fn primary(b: *std.Build, source: std.Build.LazyPath, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, front: *Module, cpu_component: *Module, cuda_component: *Module) *Module {
    const result = b.createModule(.{ .root_source_file = source, .target = target, .optimize = optimize });
    bindPrimary(result, front, cpu_component, cuda_component);
    return result;
}

pub fn bindPrimary(result: *Module, front: *Module, cpu_component: *Module, cuda_component: *Module) void {
    inherit(result, cuda_component);
    bind(result, "ethereum_frontend_component", front);
    bind(result, "ethereum_cpu_component", cpu_component);
    bind(result, "ethereum_cuda_component", cuda_component);
    bind(result, "legacy_riscv_frontend", front);
    bind(result, "legacy_riscv_cpu_integration", cpu_component);
}
