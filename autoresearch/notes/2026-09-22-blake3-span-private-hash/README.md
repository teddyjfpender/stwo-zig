# Private BLAKE3 Span identity hash assembly

Added live and message-free trusted constructors for full Span/job hashing.
The assembly removes public message boundaries and replaces them with the exact
identity byte routes; fixed hash constants and full claimed-digest sinks remain.
The trusted constructor takes no statement values. The existing full hash witness
and typed byte router own all hashing and routing equations.

The focused ReleaseSafe statement-codec gate passed in 17 seconds (999 MB peak
RSS). Both identity purposes match native hashes. Fixed route metadata and retained
boundaries agree between live and trusted construction. An exact full hash-wire
ledger closes with explicit caller-byte producers, and fails when the digest sink
is changed. These test producers are public fixtures; they do not constitute a
production statement proof. Earlier canonical input and graph-binding checks also
remain in the gate. No full STARK proof or speedup is claimed here.

Remaining: join the authenticated parent plan, canonical encoding and private
hash in one production proof assembly, bind digest sinks to production identity
claims, combine purposes without duplicate schedules, and migrate remaining
memory/continuation commitments and artifact/key admission.
