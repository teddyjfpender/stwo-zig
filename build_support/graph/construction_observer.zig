//! Derives the configured build closure from Zig's constructed step graph.

const std = @import("std");
const modules = @import("modules.zig");

pub const ProductIdentity = struct {
    product_id: []const u8,
    frontend: []const u8,
    backend: []const u8,
    role: []const u8,
    protocol_manifest: []const u8,
};

pub const Snapshot = struct {
    products: []const ProductIdentity,
    constructors: []const []const u8,
    module_roots: []const []const u8,
    generated_module_roots: []const []const u8,
    dependency_module_roots: []const []const u8,
    external_tools: []const []const u8,
    runtime_probes: []const []const u8,
};

const ProductRecord = struct {
    owner: *std.Build,
    identity: ProductIdentity,
    next: ?*ProductRecord,
};

const StringRecord = struct {
    owner: *std.Build,
    value: []const u8,
    next: ?*StringRecord,
};

var recorded_products: ?*ProductRecord = null;
var recorded_constructors: ?*StringRecord = null;
var recorded_tools: ?*StringRecord = null;

/// Records the product after its real constructor has returned. Declarations
/// alone never enter the observed construction ledger.
pub fn recordProduct(b: *std.Build, product: modules.Product) void {
    const record = b.allocator.create(ProductRecord) catch @panic("out of memory");
    record.* = .{
        .owner = b,
        .identity = .{
            .product_id = product.name,
            .frontend = @tagName(product.frontend),
            .backend = @tagName(product.backend),
            .role = @tagName(product.role),
            .protocol_manifest = product.protocol_features,
        },
        .next = recorded_products,
    };
    recorded_products = record;
}

/// Records an actual constructor call at its call site.
pub fn recordConstructor(b: *std.Build, name: []const u8) void {
    recordString(b, &recorded_constructors, name);
}

/// Child.run executes during graph construction and is invisible to the Zig
/// step graph, so configure-time command sites record the tool explicitly.
pub fn recordConfigureTool(b: *std.Build, name: []const u8) void {
    recordString(b, &recorded_tools, std.fs.path.basename(name));
}

fn recordString(b: *std.Build, head: *?*StringRecord, value: []const u8) void {
    const record = b.allocator.create(StringRecord) catch @panic("out of memory");
    record.* = .{ .owner = b, .value = value, .next = head.* };
    head.* = record;
}

pub fn observe(b: *std.Build) Snapshot {
    var observer = Observer.init(b);
    var product = recorded_products;
    while (product) |record| : (product = record.next) {
        if (record.owner == b) observer.putProduct(record.identity);
    }
    var constructor = recorded_constructors;
    while (constructor) |record| : (constructor = record.next) {
        if (record.owner == b) observer.put(&observer.constructors, record.value);
    }
    var tool = recorded_tools;
    while (tool) |record| : (tool = record.next) {
        if (record.owner == b) observer.put(&observer.external_tools, record.value);
    }
    var top_levels = b.top_level_steps.iterator();
    while (top_levels.next()) |entry| observer.visitStep(&entry.value_ptr.*.step);
    return .{
        .products = observer.sortedProducts(),
        .constructors = observer.sortedKeys(&observer.constructors),
        .module_roots = observer.sortedKeys(&observer.module_roots),
        .generated_module_roots = observer.sortedKeys(&observer.generated_module_roots),
        .dependency_module_roots = observer.sortedKeys(&observer.dependency_module_roots),
        .external_tools = observer.sortedKeys(&observer.external_tools),
        .runtime_probes = observer.sortedKeys(&observer.runtime_probes),
    };
}

const Observer = struct {
    b: *std.Build,
    visited_steps: std.AutoHashMap(*std.Build.Step, void),
    visited_modules: std.AutoHashMap(*std.Build.Module, void),
    products: std.StringArrayHashMap(ProductIdentity),
    constructors: std.StringHashMap(void),
    module_roots: std.StringHashMap(void),
    generated_module_roots: std.StringHashMap(void),
    dependency_module_roots: std.StringHashMap(void),
    external_tools: std.StringHashMap(void),
    runtime_probes: std.StringHashMap(void),

    fn init(b: *std.Build) Observer {
        return .{
            .b = b,
            .visited_steps = std.AutoHashMap(*std.Build.Step, void).init(b.allocator),
            .visited_modules = std.AutoHashMap(*std.Build.Module, void).init(b.allocator),
            .products = std.StringArrayHashMap(ProductIdentity).init(b.allocator),
            .constructors = std.StringHashMap(void).init(b.allocator),
            .module_roots = std.StringHashMap(void).init(b.allocator),
            .generated_module_roots = std.StringHashMap(void).init(b.allocator),
            .dependency_module_roots = std.StringHashMap(void).init(b.allocator),
            .external_tools = std.StringHashMap(void).init(b.allocator),
            .runtime_probes = std.StringHashMap(void).init(b.allocator),
        };
    }

    fn visitStep(self: *Observer, step: *std.Build.Step) void {
        const entry = self.visited_steps.getOrPut(step) catch @panic("out of memory");
        if (entry.found_existing) return;
        switch (step.id) {
            .compile => {
                const compile: *std.Build.Step.Compile = @fieldParentPtr("step", step);
                self.visitModule(compile.root_module);
            },
            .run => {
                const run: *std.Build.Step.Run = @fieldParentPtr("step", step);
                if (run.producer == null and run.argv.items.len != 0) switch (run.argv.items[0]) {
                    .bytes => |command| self.put(&self.external_tools, std.fs.path.basename(command)),
                    else => {},
                };
            },
            else => {},
        }
        for (step.dependencies.items) |dependency| self.visitStep(dependency);
    }

    fn visitModule(self: *Observer, module: *std.Build.Module) void {
        const entry = self.visited_modules.getOrPut(module) catch @panic("out of memory");
        if (entry.found_existing) return;
        if (module.root_source_file) |root| self.putModulePath(root);
        var frameworks = module.frameworks.iterator();
        while (frameworks.next()) |framework| self.put(
            &self.runtime_probes,
            self.b.fmt("{s}.framework", .{framework.key_ptr.*}),
        );
        for (module.link_objects.items) |link| switch (link) {
            .system_lib => |library| self.put(
                &self.runtime_probes,
                if (std.mem.eql(u8, library.name, "objc")) "libobjc" else library.name,
            ),
            .c_source_file => |source| self.putModulePath(source.file),
            .c_source_files => |sources| for (sources.files) |path| self.put(
                &self.module_roots,
                self.b.pathJoin(&.{ sources.root.getDisplayName(), path }),
            ),
            else => {},
        };
        var imports = module.import_table.iterator();
        while (imports.next()) |item| self.visitModule(item.value_ptr.*);
    }

    fn put(_: *Observer, map: *std.StringHashMap(void), value: []const u8) void {
        map.put(value, {}) catch @panic("out of memory");
    }

    fn putModulePath(self: *Observer, path: std.Build.LazyPath) void {
        switch (path) {
            .src_path => |source| self.put(&self.module_roots, source.sub_path),
            .cwd_relative => |source| self.put(&self.module_roots, source),
            .generated => |generated| {
                const step_name = generated.file.step.name;
                if (generatedOutputDirectory(step_name)) |directory| {
                    self.put(
                        &self.generated_module_roots,
                        self.b.fmt("generated:{s}:", .{directory}),
                    );
                } else {
                    self.put(&self.generated_module_roots, self.b.fmt(
                        "generated:{s}:{s}",
                        .{ step_name, generated.sub_path },
                    ));
                }
            },
            .dependency => |dependency| self.put(&self.dependency_module_roots, self.b.fmt(
                "dependency:{s}:{s}",
                .{ dependency.dependency.builder.pkg_hash, dependency.sub_path },
            )),
        }
    }

    fn putProduct(self: *Observer, identity: ProductIdentity) void {
        const key = self.b.fmt("{s}|{s}|{s}|{s}|{s}", .{
            identity.product_id,
            identity.frontend,
            identity.backend,
            identity.role,
            identity.protocol_manifest,
        });
        self.products.put(key, identity) catch @panic("out of memory");
    }

    fn sortedProducts(self: *Observer) []const ProductIdentity {
        const result = self.b.allocator.alloc(ProductIdentity, self.products.count()) catch
            @panic("out of memory");
        var iterator = self.products.iterator();
        var index: usize = 0;
        while (iterator.next()) |entry| : (index += 1) result[index] = entry.value_ptr.*;
        std.mem.sort(ProductIdentity, result, {}, struct {
            fn lessThan(_: void, lhs: ProductIdentity, rhs: ProductIdentity) bool {
                if (!std.mem.eql(u8, lhs.product_id, rhs.product_id))
                    return std.mem.lessThan(u8, lhs.product_id, rhs.product_id);
                if (!std.mem.eql(u8, lhs.backend, rhs.backend))
                    return std.mem.lessThan(u8, lhs.backend, rhs.backend);
                return std.mem.lessThan(u8, lhs.role, rhs.role);
            }
        }.lessThan);
        return result;
    }

    fn sortedKeys(self: *Observer, map: *std.StringHashMap(void)) []const []const u8 {
        const result = self.b.allocator.alloc([]const u8, map.count()) catch @panic("out of memory");
        var iterator = map.keyIterator();
        var index: usize = 0;
        while (iterator.next()) |key| : (index += 1) result[index] = key.*;
        std.mem.sort([]const u8, result, {}, struct {
            fn lessThan(_: void, lhs: []const u8, rhs: []const u8) bool {
                return std.mem.lessThan(u8, lhs, rhs);
            }
        }.lessThan);
        return result;
    }
};

/// `Run.addOutputDirectoryArg` appends ` (basename)` to the generating step
/// name. Every file below that directory is one generated module root, so the
/// configure manifest records the authenticated directory boundary once.
fn generatedOutputDirectory(step_name: []const u8) ?[]const u8 {
    if (!std.mem.endsWith(u8, step_name, ")")) return null;
    const open = std.mem.lastIndexOfScalar(u8, step_name, '(') orelse return null;
    if (open == 0 or step_name[open - 1] != ' ' or open + 1 >= step_name.len - 1)
        return null;
    return step_name[open + 1 .. step_name.len - 1];
}

test "generated output directories collapse to one configure root" {
    try std.testing.expectEqualStrings(
        "cairo-witness-cpu-aot",
        generatedOutputDirectory(
            "run exe cairo-witness-cpu-codegen (cairo-witness-cpu-aot)",
        ).?,
    );
    try std.testing.expect(generatedOutputDirectory("options") == null);
}
