# Guest service checkpoint

These are exact execution/oracle receipts, not physical proof timings. The
historical mainnet chain-10 corpus and input hashes are unchanged. Benchmarks
were captured while development builds ran, so wall times are not promoted.

* Heavy block 121065789: 1,776,180,154 instructions and 30,316,758 service RAM
  word transitions; full pre-turn guest: 2,500,418,167 instructions. The earlier
  Montgomery adapter: 1,376,966,523 instructions but 162,809,929 service RAM words.
  Instruction count alone therefore does not select the winning prover variant.
* User block 121057303: 5,994,515 instructions with the allocator regression
  enabled, versus 6,394,106 in the prior full guest. Five small/user blocks pass
  native eager/lazy parity plus exact Unicorn retirement/register/service checks.
* Size optimization shrinks text, but increases executed instructions; it is
  retained as an experiment rather than promoted. Opt level 2 also loses here.
* Kona MPT: 18 offline tests pass, including randomized insert/delete properties;
  two explicitly online list-walker tests are excluded. Revm bytecode: 46 tests
  pass against the pinned alloy-primitives 1.6.1 ABI. Provider: six tests pass,
  covering the earlier four service cases and two pairing-cache boundary suites.

Changes follow the evmone lessons: use the existing admitted curve/scanner
relations, avoid zero-then-fill packets, preserve exact input validation, reduce
allocation/copy passes, and measure service RAM as well as instructions. The MPT
decoder scans bounded payloads once and borrows compact paths. The allocator now
publishes intrusive metadata through explicit volatile stores; an opt-in guest
checks logical 1..24-byte allocations across alignments 1..64 through Rust's real
allocator ABI. No regression assertions run in the default guest.

Build/source manifests from this development checkpoint may include concurrent
uncompiled edits; the ELF and input hashes are authoritative for these results.
A clean final rebuild and full proof/receiver receipts remain separate gates.

Positive control: restoring the previous allocator and enabling the same guest
reuse assertions with opt level `s` reproduces `MisalignedAddress` during block
121003241, after 5,999,588 instructions. The small startup checks alone do not
catch this context-dependent optimization. The mainnet regression does, and the
fixed checked guest completes all five oracle cases.
