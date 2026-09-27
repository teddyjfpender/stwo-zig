# Empty native table partition

`TableJoin.onNative` already skipped the projection loader when the independently reconstructed native slot roster was empty. The new `block_v5_empty_native_tables_v1` makes that branch explicit and rejects an inferred zero from ordinary-opcode absence alone.

A valid empty branch has no opcode components and no infrastructure, all native fixed/main/interaction column counts are zero, all six independently derived lookup demands are zero, and the native slot roster is empty. All retirements are external and equal the admitted step count. A clock-only native shape has three real projection slots, one range20 request and one range88 request per clock row; it follows the existing nonempty proof path.

The receiver derivation checks the validated shape, public admission, independent template/catalog, B5SS execution entry, fixed/main roots and instance ID against its fresh native-v3 verifier output. It draws the common universal challenges and requires the empty native open claim to equal the independently derived public PC/clock compensation. That compensation is retained for the caller state proof to close. There is no invented zero STARK, empty proof wire, waived native verification or caller-supplied zero claim.

The producer warm stage and receiver import the same absence policy. The helper and bounded semantic unit tests are AST-clean; runtime semantic qualification and a genuine caller-only native/global proof remain pending. Unit receipts are explicitly synthetic identity/branch inputs and confer no proof authority.

For the final equation, let native and caller six-table consumers be `Tn` and `Tc`, and packed sidecar byte requests be `B`. Each independently field-safe group closes `TableProvider + Tn + Tc + B = 0`. `Tn` already appears in the native open claim and `Tc` already appears in the precompile open claim. Consequently the global audit adds `TableProvider + B`, without adding the reported `caller_table_sum` again. Public PC/clock, program and real memory partitions close separately. Native auxiliary clock-memory requests are subtracted once; the dedicated caller roster's authenticated auxiliary partition is zero.
