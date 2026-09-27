# BLAKE3 full CSP ECDSA guest at canonical parameters

Ethereum leaf artifacts now share one implementation specialized to immutable
v2/BLAKE2s and new v6/BLAKE3. Reused metadata section encoders preserve v2 bytes;
IdentityForVersion binds v6 inside the identity section and gives its metadata
hash a distinct domain. Header hasher ID 3 admits v5 guest and v6 Ethereum
products. CSP selects codec from the trusted Engine's canonical hasher/channel/
Merkle-channel types, not from untrusted encoded bytes. Ethereum proving and
verification remain their existing generic implementations.

Actual CPU ECDSA precompile guest passes at 70 queries, 26 PoW bits, blowup log1,
fold1, using 16 workers and ReleaseFast. The gate freshly decodes and independently
verifies the full guest, rejects input/ELF/proof substitutions, and checks recovery
and low-S routing. Fixture source and both ELF pins match the precompile manifest;
input matches its canonical manifest pin. See fixture-pins.json and host.json.

One qualification sample:
- execution (including recovery selection): 1,978,375 ns (0.001978 s)
- proving (including witness construction): 2,489,485,500 ns (2.489486 s)
- independent verification: 188,205,792 ns (0.188206 s)
- guest cycles: 1,828; serialized inner proof: 3,748,258 bytes

Serialization and command startup are outside proving time. This is one dirty-
worktree qualification sample, not an A/B speedup verdict, subsecond result or
complete CPU/Metal CSP suite. Production defaults remain BLAKE2s.

Gate results: canonical BLAKE3 CSP ECDSA 1/1 tests, 3 s /1 GiB reported MaxRSS,
compile 57 s /3 GiB; focused artifact gate 13/13 tests, 8 s /4 MiB, compile
9 s /986 MiB. Identity tests reject cross-version decoding and changed metadata;
legacy vectors/codec mutation and ownership tests pass. No leaks reported.

Command:
STWO_CSP_FIXTURE_ROOT=/Users/theodorepender/code/cryptography/stwo-zig/vectors/riscv_csp python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-csp-ecdsa -Doptimize=ReleaseFast --summary all

Remaining: ordinary/segment artifact migration, CLI/benchmark suite identification
and u64 transcript receipts, coordinated defaults, Metal implementation, complete
canonical CSP matrix; production recursion keys/multilevel qualification and
full-profile performance improvements remain incomplete.
