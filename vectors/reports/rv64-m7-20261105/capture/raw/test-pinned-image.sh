#!/bin/bash
set -euo pipefail
cd /workspace/m3/src/m7-capture
export ZIG_GLOBAL_CACHE_DIR=/workspace/m3/cache/zig-global
flock -w 3600 /workspace/m3/locks/build.3.lock /workspace/zig/zig build test-riscv64-word16-execution-coordinator '-Driscv-test-filter=resident pinned image' -Doptimize=ReleaseSafe -Dcpu=x86_64_v4+sha -Dimplementation-commit=26ca2079314833704137aae900955ece81ae49e9 -Dimplementation-tree=727ca80f8856be92acfb632bf987a05a5e65f0ae -Dimplementation-dirty=true -Dimplementation-dirty-content-sha256=647ba9a4b09f8be3c5476ffbc19c977a69e2cce9e3ffff335aa3858a386f42f2 -j12 --cache-dir .zig-cache
flock -w 3600 /workspace/m3/locks/build.3.lock /workspace/zig/zig build test-riscv64-word16-program-metadata '-Driscv-test-filter=capture program view' -Doptimize=ReleaseSafe -Dcpu=x86_64_v4+sha -Dimplementation-commit=26ca2079314833704137aae900955ece81ae49e9 -Dimplementation-tree=727ca80f8856be92acfb632bf987a05a5e65f0ae -Dimplementation-dirty=true -Dimplementation-dirty-content-sha256=647ba9a4b09f8be3c5476ffbc19c977a69e2cce9e3ffff335aa3858a386f42f2 -j12 --cache-dir .zig-cache
