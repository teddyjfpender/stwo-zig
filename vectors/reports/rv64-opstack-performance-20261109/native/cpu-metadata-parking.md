# Bounded inactive CPU metadata

`Resources.park_cpu_metadata=true` enables producer-only advice parking. The protocol, source declarations, batch geometry and fresh receiver do not change. Default remains false.

The capture metadata is already moved rather than duplicated, and the original 56 bytes per retirement are still needed after the manifest for the local binding witness. The producer now writes one immutable, unlinked file per captured CPU shard. It restores only the active shard for source construction and local GKR sealing, retires that heap view, and restores the same file for post-manifest completion. No second file write or production rehash is required. All later constraints and authenticated obligations remain present.

Files reserve the same `Store` disk quota as MAIN/FIXED, with page-rounded admission before writes. After independently constructing FIXED authority, the uncached route checks its actual reservation plus conservative remaining MAIN and metadata payload. A cached route retains its separately enforced growth reservation and fails closed when the remainder is insufficient. No quota increase or uncharged mapping is used.

Exclusive ownership, exact source descriptor and restored slice identity are checked. Metadata has an explicitly checked padding-free layout (five u64, three u32, one u32, 56 bytes). File length and SHA256 are checked before a restored slice is published. Restore failures leave the file token and empty source unchanged. Test builds also verify that source construction and local sealing leave the metadata digest unchanged before retiring the view; production const consumers avoid that redundant second hash. Shared/sealed metadata owners are refused.

The actual 796,406-step block with CPU, 338 Keccak calls and 34 SHA calls freshly verifies. Its 5,317,432-byte bundle has SHA256 `c18d85864cead50203bc0354f86c91048ec29dd7750add7d2651fc2d2967abbf`, exactly matching the unparked schema-2 control. Global closure, terminal output, wrong-policy and proof-mutation controls pass. Final heap and external reservations are zero. This is a correctness/memory qualification, not a speed comparison.

No heavy block execution or proof was rerun. Source-only arithmetic estimates that replacing 13.34 GB of retained heavy metadata with one 235 MB active slice lowers the earlier diagnostic payload from 35.92 GB to 22.81 GB. That excludes source construction and PCS scratch, so it does not establish a whole-worker peak or an end-to-end benchmark.
