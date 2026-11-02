# Existing delegation integrations

These directories own the existing concrete Keccak, secp256k1, DIV/REM and MUL
sources, native diagnostics, fixtures and receiving CLIs. `common/` holds their
shared journal, joined source ownership, borrowed-buffer admission and arithmetic
residual diagnostic. The legacy joined CPU coordinator remains at
`rv64_keccak_cpu.zig`; request, batch-receipt and distributed-manifest authorities
keep their existing locations.

This relocation changes import paths and build entry ownership. It does not
change any statement, transcript, provider layout, polynomial or native kernel.
The 24 moved bodies are checked against their predecessor after normalizing
import literals. Existing public AIR aliases remain unchanged.

Zig nested roots cannot import outside their own directory. The two integration
package-root entry shims therefore import these actual nested sources using
statically enumerated build IDs. Only the registered test/tool paths are
accepted. Tests stay in the root module, preserving discovery and guard counts;
no test namespace is exported by the production integration module. Executable
names and argument contracts are unchanged.
