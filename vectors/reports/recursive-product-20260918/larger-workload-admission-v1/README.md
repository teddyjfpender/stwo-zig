# Larger recursive workload admission

The maintained tree command now selects 1/4/16 memory addresses from its pinned
admission. Larger segment-to-parent folds require a separately pinned boundary
profile; topology is not taken from candidate proof data. Parent command tests
cover missing, mismatched and duplicate pins, wrong child family and malformed
topology. Five focused command tests and 14 ownership tests pass. A genuine
one-address parent through the new explicit profile passes 28 fresh-process
checks and reproduces the prior key, claims and proof exactly.

The leaf setup tool supports:
`recursive-segment-v2-leaf-key-setup --export-workload CONFIG SHA256 NEW_DIRECTORY`.
CONFIG selects version 1, memory_addresses, initial_memory_word, segment_count
and proof_profile. Execution is checked against the independent instruction and
memory model before expected statements are exported. This stage creates no
keys or proofs. Its setup-manifest.json then feeds the existing pinned leaf-key
setup command.

Retained 16-address workloads cover 1/2/4/8 segments and seeds 13/14: 30 expected
statements, all hash-checked, distinct between seeds with matching wire lengths.
Separate seed-13 setup produced 15 leaf keys, with no outer proofs. Wrong config
pins, unsupported segment counts and unsupported address counts fail before
creating output.

This is admission evidence, not completion of the larger proof ladder. Parent
expected statements/topology, parent key setup, complete CPU/Metal trees and
memory/verification measurements remain outstanding. These small development
workloads do not establish production security or Ethereum readiness.
