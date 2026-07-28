const std = @import("std");
const backend = @import("stwo_cairo_metal_integration").process_backend;
const runner = @import("stwo_cairo_metal_integration").process_runner;

test {
    std.testing.refAllDecls(backend);
    std.testing.refAllDecls(runner);
}
