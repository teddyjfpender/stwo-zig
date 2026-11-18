//! Canonical provider execution of consumer-owned waist laws.
const std = @import("std");
const graph = @import("../graph/modules.zig");

fn findPublicModule(b: *std.Build, facade: *std.Build.Module, name: []const u8) *std.Build.Module {
    var pending: std.ArrayList(*std.Build.Module) = .empty;
    var seen = std.AutoHashMap(*std.Build.Module, void).init(b.allocator);
    pending.append(b.allocator, facade) catch @panic("OOM");
    var selected: ?*std.Build.Module = null;
    var index: usize = 0;
    while (index < pending.items.len) : (index += 1) {
        const module = pending.items[index];
        const entry = seen.getOrPut(module) catch @panic("OOM");
        if (entry.found_existing) continue;
        if (module.import_table.get(name)) |candidate| {
            if (selected != null and selected.? != candidate) @panic("consumer public module identity is ambiguous");
            selected = candidate;
        }
        for (module.import_table.values()) |child| pending.append(b.allocator, child) catch @panic("OOM");
    }
    return selected orelse std.debug.panic("missing actual consumer public module {s}", .{name});
}

fn reachesModule(b: *std.Build, root: *std.Build.Module, selected: *std.Build.Module) bool {
    var pending: std.ArrayList(*std.Build.Module) = .empty;
    var seen = std.AutoHashMap(*std.Build.Module, void).init(b.allocator);
    pending.append(b.allocator, root) catch @panic("OOM");
    var index: usize = 0;
    while (index < pending.items.len) : (index += 1) {
        const module = pending.items[index];
        if (module == selected) return true;
        const entry = seen.getOrPut(module) catch @panic("OOM");
        if (entry.found_existing) continue;
        for (module.import_table.values()) |child| pending.append(b.allocator, child) catch @panic("OOM");
    }
    return false;
}

// Assert actual link inputs, not just the presence of a helper invocation.
fn assertMetalRuntime(b: *std.Build, artifact: *std.Build.Step.Compile) void {
    const metal = @import("../backends/metal.zig");
    const expected = @import("stwo_metal_backend").runtime_source.flags(b, b.pathFromRoot(metal.runtime_source));
    var sources: usize = 0;
    var objc = false;
    for (artifact.root_module.link_objects.items) |object| switch (object) {
        .c_source_file => |source_file| {
            if (!std.mem.eql(u8, source_file.file.getPath(b), b.pathFromRoot(metal.runtime_source))) continue;
            if (source_file.flags.len != expected.len) @panic("CDC Metal runtime flags drifted");
            for (source_file.flags, expected) |actual, wanted| if (!std.mem.eql(u8, actual, wanted)) {
                @panic("CDC Metal runtime lost ARC or source-closure identity");
            };
            sources += 1;
        },
        .system_lib => |library| if (std.mem.eql(u8, library.name, "objc")) {
            objc = true;
        },
        else => {},
    };
    if (sources != 1 or !objc or artifact.root_module.link_libc != true or
        !artifact.root_module.frameworks.contains("Foundation") or !artifact.root_module.frameworks.contains("Metal"))
        @panic("CDC actual Metal consumer is missing its canonical native runtime linkage");
}

fn selectedProtocol(b: *std.Build, facade: *std.Build.Module) graph.ProtocolModules {
    return graph.ProtocolModules{
        .core = findPublicModule(b, facade, "stwo_core"),
        .backend_contracts = findPublicModule(b, facade, "stwo_backend_contracts"),
        .prover_api = findPublicModule(b, facade, "stwo_prover_api"),
        .prover = findPublicModule(b, facade, "stwo_prover_engine"),
    };
}

// Executed by the existing consumer BUILD harness, not a runtime backend API.
fn assertCudaFactoryCallerBindings(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, facade: *std.Build.Module, product: graph.Product) void {
    const selected = selectedProtocol(b, facade);
    const actual = graph.createCudaBackend(b, selected, product, target, optimize);
    if (actual.import_table.get("stwo_core") != selected.core or
        actual.import_table.get("stwo_prover_engine") != selected.prover or
        actual.import_table.get("stwo_backend_contracts") != selected.backend_contracts)
        @panic("CUDA factory lost caller-selected protocol identity");
    if (actual.import_table.get("stwo_prover_api") != null)
        @panic("CUDA factory acquired undeclared blanket protocol imports");
}

fn addMissingConsumerModules(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, facade: *std.Build.Module, product: graph.Product) void {
    // Construct the missing CUDA seam through its real factory and selected predecessors.
    const cuda = @import("../graph/integrations.zig").createRiscVCuda(b, selectedProtocol(b, facade), product, target, optimize, findPublicModule(b, facade, "stwo_cuda_backend"), findPublicModule(b, facade, "stwo_riscv_frontend"), findPublicModule(b, facade, "stwo_riscv_cpu_integration"));
    facade.addImport("stwo_riscv_cuda_integration", cuda);
    // These actual package adapters are absent from the deprecated SDK facade.
    // Their contracts own roots and dependencies; this list selects composition,
    // never defines a second API/dependency registry or a runtime product.
    for ([_][]const u8{
        "src/frontends/sm83",
        "src/integrations/sm83_cpu",
        "src/integrations/sm83_metal",
        "src/integrations/riscv_metal",
        "src/integrations/circuit_metal",
    }) |directory| {
        const path = b.pathFromRoot(b.fmt("{s}/package.contract.json", .{directory}));
        const bytes = std.fs.cwd().readFileAlloc(b.allocator, path, 1 << 20) catch @panic("read consumer owner contract");
        const payload = (std.json.parseFromSlice(std.json.Value, b.allocator, bytes, .{}) catch @panic("parse consumer owner contract")).value;
        const public = payload.object.get("public_modules").?.object;
        if (public.count() != 1) @panic("CDC adapter requires one exact public owner root");
        const name = public.keys()[0];
        const module = graph.create(b, .{ .product = product, .root_source_file = b.fmt("{s}/{s}", .{ directory, public.values()[0].string }), .target = target, .optimize = optimize });
        var dependencies = payload.object.get("dependencies").?.object.iterator();
        while (dependencies.next()) |entry| module.addImport(entry.key_ptr.*, findPublicModule(b, facade, entry.key_ptr.*));
        facade.addImport(name, module);
    }
}

fn selectedOwnerModule(b: *std.Build, registration: @import("package_dependencies.zig").Consumer, package_name: []const u8) []const u8 {
    const selected = registration.owner_module orelse return package_name;
    const owned = @import("../graph/package_ownership.zig").resolve(registration.root) orelse @panic("unowned consumer module selection");
    const directory = registration.root[0 .. registration.root.len - owned.sub_path.len - 1];
    const bytes = std.fs.cwd().readFileAlloc(b.allocator, b.pathFromRoot(b.fmt("{s}/package.contract.json", .{directory})), 1 << 20) catch @panic("read consumer module owner");
    const payload = (std.json.parseFromSlice(std.json.Value, b.allocator, bytes, .{}) catch @panic("parse consumer module owner")).value;
    if (!std.mem.eql(u8, payload.object.get("package").?.string, package_name) or
        !payload.object.get("public_modules").?.object.contains(selected))
        @panic("consumer module is not a declared public root of its owner");
    return selected;
}

pub fn add(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode, facade: *std.Build.Module, product: graph.Product) void {
    const context = .{ .b = b, .target = target, .optimize = optimize };
    const cdc = @import("package_dependencies.zig");
    addMissingConsumerModules(b, target, optimize, facade, product);
    assertCudaFactoryCallerBindings(b, target, optimize, facade, product);
    const laws = b.createModule(.{ .root_source_file = b.path("build_support/products/consumer_laws.zig"), .target = target, .optimize = optimize });
    const source_check = context.b.addSystemCommand(&.{ "python3", "scripts/repo/check_package_workspace.py" });
    source_check.setCwd(context.b.path("."));
    for (cdc.waist_providers) |provider| {
        const target_label = context.b.fmt("test-cdc-{s}", .{provider.name});
        const target_name = context.b.allocator.dupe(u8, target_label) catch @panic("OOM");
        for (target_name) |*character| if (character.* == '_') {
            character.* = '-';
        };
        const step = context.b.step(target_name, "Run registered consumer-owned waist contracts");
        const canonical = findPublicModule(context.b, facade, provider.name);
        for (cdc.providerConsumers(context.b, provider.directory)) |registration| {
            const is_product = std.mem.startsWith(u8, registration.id, "product:");
            const owner_name = if (is_product) registration.id["product:".len..] else if (std.mem.startsWith(u8, registration.id, "package:")) registration.id["package:".len..] else @panic("unsupported consumer kind");
            if (is_product and (!std.mem.eql(u8, owner_name, product.name) or !std.mem.eql(u8, registration.route, registration.id))) @panic("consumer does not name the actual constructed SDK product");
            if (is_product and registration.owner_module != null) @panic("product consumer cannot select a package owner module");
            const actual_owner_name = if (is_product) owner_name else selectedOwnerModule(context.b, registration, owner_name);
            const owner = if (is_product) facade else findPublicModule(context.b, facade, actual_owner_name);
            const bound = if (std.mem.eql(u8, registration.route, "injected:interop_postcard")) (owner.import_table.get("interop_postcard") orelse @panic("consumer missing actual postcard injection")).import_table.get(provider.name) orelse @panic("postcard missing canonical provider") else owner.import_table.get(provider.name) orelse std.debug.panic("consumer {s} missing declared provider {s}; route={s}; root={s}", .{ registration.id, provider.name, registration.route, registration.root });
            if (bound != canonical) @panic("consumer/provider module identity mismatch");
            const root = graph.create(context.b, .{ .product = product, .root_source_file = registration.root, .target = context.target, .optimize = context.optimize });
            for (registration.imports) |name| {
                const binding = if (std.mem.eql(u8, name, "waist_consumer_laws")) laws else if (std.mem.eql(u8, name, provider.name)) bound else if (std.mem.eql(u8, name, actual_owner_name)) owner else owner.import_table.get(name) orelse @panic("unbound consumer public import");
                root.addImport(name, binding);
            }
            const name = context.b.fmt("cdc-{s}-{s}-{s}", .{ provider.name, owner_name, @tagName(context.optimize) });
            const artifact = context.b.addTest(.{ .name = name, .root_module = root, .filters = registration.tests });
            if (context.target.result.os.tag == .macos and reachesModule(context.b, root, findPublicModule(context.b, facade, "stwo_metal_backend"))) {
                @import("../backends/metal.zig").linkRuntime(context.b, artifact);
                assertMetalRuntime(context.b, artifact);
            }
            artifact.step.dependOn(&source_check.step);
            const run = context.b.addRunArtifact(artifact);
            run.has_side_effects = true;
            run.setCwd(context.b.path("."));
            const guard = context.b.allocator.create(ConsumerDiscoveryGuard) catch @panic("OOM");
            guard.* = .{
                .step = std.Build.Step.init(.{ .id = .custom, .name = name, .owner = context.b, .makeFn = ConsumerDiscoveryGuard.make }),
                .run = run,
                .expected = registration.tests,
            };
            guard.step.dependOn(&run.step);
            step.dependOn(&guard.step);
            const install = &context.b.addInstallArtifact(artifact, .{ .dest_sub_path = name }).step;
            step.dependOn(install);
            const alias_name = cdc.consumerAliasName(context.b, provider.name, registration.id);
            const alias = context.b.step(alias_name, "Run one exact registered consumer contract image");
            alias.dependOn(&guard.step);
            alias.dependOn(install);
            if (alias.dependencies.items.len != 2 or alias.dependencies.items[0] != &guard.step or alias.dependencies.items[1] != install)
                @panic("consumer alias lost its original discovery guard or installed artifact");
        }
    }
}

const ConsumerDiscoveryGuard = struct {
    step: std.Build.Step,
    run: *std.Build.Step.Run,
    expected: []const []const u8,

    fn make(step: *std.Build.Step, _: std.Build.Step.MakeOptions) anyerror!void {
        const self: *@This() = @fieldParentPtr("step", step);
        const metadata = self.run.cached_test_metadata orelse return step.fail("consumer contract run has no discovery metadata", .{});
        if (metadata.names.len != self.expected.len)
            return step.fail("consumer contract expected {d} cases, found {d}", .{ self.expected.len, metadata.names.len });
        for (self.expected) |name| {
            var count: usize = 0;
            for (0..metadata.names.len) |index| {
                if (std.mem.endsWith(u8, metadata.testName(@intCast(index)), name)) count += 1;
            }
            if (count != 1) return step.fail("consumer contract requires exactly one '{s}', found {d}", .{ name, count });
        }
    }
};
