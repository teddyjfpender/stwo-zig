# Post-seal source auxiliaries

Set `"retire_source_auxiliaries": true` in the JSON resource file passed to `rv64-op-native prove CONFIG OUT RESOURCES --truth-local-gkr`. Default is false. It composes with `"park_cpu_metadata": true`; neither option changes a source statement or proof schema.

After successful MAIN commitment and local GKR sealing, the producer first validates every owned LS32/LS-D64 fixed-mask shape and all SHIFT multiplicities. Only then does it free LS raw fixed masks and SHIFT head/tail histograms. Any validation failure occurs before ownership changes. It leaves the immutable P2 FIXED key and its separately leased views untouched.

LS local consumers in `services/gkr_local/native_provider.zig` and RAM consumers in `global_metadata.zig` use saved 82-byte metadata. They do not read the source's raw fixed masks. SHIFT has a real later consumer: the post-manifest binding projection. It now reads the exact physical/logical multiplicities from the already-retained packed SHIFT table MAIN whenever both head and tail histograms have retired. `word16_execution/main_ownership.zig` explicitly preserves that MAIN copy. No table, witness or summed histogram is reconstructed or allocated. Before freeing, every saved head+tail count must equal its corresponding packed MAIN cell; overflow/mismatch controls refuse without freeing.

On the frozen heavy roster this retires 1,443,987,456 bytes of LS fixed masks and 780,140,544 bytes of SHIFT histograms after their last consumer, totalling 2,224,128,000 bytes. These are exact derived source payloads, not measured RSS. No heavy execution or proof was rerun.

The actual 796,406-step block was re-proved with both metadata parking and auxiliary retirement. The full 5,317,432-byte native bundle is byte-identical to the original schema-2 control, freshly verifies, closes RAM/KIO/Wire and terminal output, and passes policy/proof mutation controls with final heap/external reservations zero. Focused ReleaseSafe multiplicity mismatch/overflow controls pass.
