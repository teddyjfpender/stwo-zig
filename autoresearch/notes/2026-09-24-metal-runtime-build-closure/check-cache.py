"""Exercise the real Zig outer cache with only a transitive include changed."""
from pathlib import Path
import hashlib, json, shutil, subprocess, tempfile
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
with tempfile.TemporaryDirectory(prefix='stwo-runtime-cache-') as directory:
    d = Path(directory)
    shutil.copy2(ROOT/'src/backends/metal/build_runtime_source.zig', d/'build_runtime_source.zig')
    (d/'build.zig').write_text('''const std = @import("std");
pub fn build(b: *std.Build) void {
    const exe = b.addExecutable(.{ .name = "probe", .root_module = b.createModule(.{
        .root_source_file = b.path("main.zig"), .target = b.standardTargetOptions(.{}),
        .optimize = .ReleaseFast,
    }) });
    exe.addCSourceFile(.{ .file = b.path("runtime.m"), .flags = @import("build_runtime_source.zig").flags(b, b.pathFromRoot("runtime.m")) });
    exe.linkLibC();
    b.installArtifact(exe);
}
''')
    (d/'main.zig').write_text('extern fn value() c_int;\npub fn main() u8 { return @intCast(value()); }\n')
    (d/'runtime.m').write_text('#import "outer.h"\nint value(void) { return VALUE; }\n')
    (d/'outer.h').write_text('#include "inner.h"\n')
    root_digest = hashlib.sha256((d/'runtime.m').read_bytes()).hexdigest()
    observations = []
    for index, value in enumerate((1, 2, 2)):
        if index < 2:
            (d/'inner.h').write_text(f'#define VALUE {value}\n')
        result = subprocess.run(['zig', 'build', '-j1', '--summary', 'all'], cwd=d, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=True)
        (HERE/f'cache-{index}.log').write_text(result.stdout)
        code = subprocess.run([str(d/'zig-out/bin/probe')], cwd=d).returncode
        assert code == value, (index, code, value)
        assert hashlib.sha256((d/'runtime.m').read_bytes()).hexdigest() == root_digest
        binary_digest = hashlib.sha256((d/'zig-out/bin/probe').read_bytes()).hexdigest()
        observations.append(dict(index=index, expected=value, actual=code, binary_sha256=binary_digest))
    assert observations[0]['binary_sha256'] != observations[1]['binary_sha256']
    assert observations[1]['binary_sha256'] == observations[2]['binary_sha256']
    assert 'cached' in (HERE/'cache-2.log').read_text()
    (HERE/'cache-results.json').write_text(json.dumps(observations, indent=2)+'\n')
    print('Transitive-only edit rebuilt the executable; unchanged third build reused it.')
