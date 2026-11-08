# PCS aggregate lengths above 32 bits

The largest recursive leaf passed joined INTER retirement and composition, then
failed `DevicePcsExportSizeExceeded`. The legacy transport header encoded four
aggregate cell counts as u32. Its total expanded source cells exceed 2^32,
although rolling PCS allocates one source tree at a time. This aggregate limit
is distinct from physical buffer capacity. Column offsets were already u64.

Representable requests retain the exact 24-word version-2 header. Requests
requiring high halves use a 28-word version-3 header, with four high words for
coefficient, expanded, combined coefficient and combined expanded totals.
The native outer request ABI, proof wire, transcript and security profile do
not change. The native parser accepts both header versions, validates lengths,
reserved fields and counts, and uses u64 throughout offset/size arithmetic.
A conservative 2^48-word ceiling is above every valid bounded inventory and
keeps all following sums and byte products overflow-free. Allocation still
passes through the same 28GiB owner cap and scoped leases.

The runtime advertises `stwo_rv64_pcs_request_version`. An old runtime receives
only version2; a large request fails explicitly instead of truncating a total.
Debug file export retains version2. No host warehouse or CPU fallback is added.

Seven host geometry/framing tests pass, including an actual 513-column
metadata-only request exceeding 2^32 expanded cells, capability refusal,
legacy-header retention, exact high-half reconstruction and malformed native
headers. C++ parser tests run through the prefix host-test target and remain
enabled in optimized/NDEBUG builds. All three production semantic checks pass.
Tiny GPU cold/warm V2-framed proofs match CPU controls on old and new
runtimes, with fresh receiver acceptance. Actual V3 largest-leaf execution
and recovery remain separate qualification gates.
