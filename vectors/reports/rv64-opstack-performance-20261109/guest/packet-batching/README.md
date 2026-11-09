# Experimental Miller packet retention

This is an explicit **`pairing-packet-batching`** Cargo feature. The existing
selected guest and ordinary `pairing-sparse-service` path keep the per-group
client. No heavy execution or proving run was launched, and this candidate is
not promoted. [Receipt](receipt.json) separates measurements from the model.

Each Miller line applies the same 640-byte service to several active groups.
The candidate initializes one caller-owned packet, retains its canonical
12-coordinate accumulator across those calls, replaces only the eight line
and point coordinates, and decodes once. All 80 words are initialized before
forming a packet reference. It uses no Arkworks layout casts, trusted host
answers or new service ABI. Calls remain in the same order, with the same
inputs and canonical results. Packet addresses and RAM access histories change;
old proofs cannot be substituted.

The frozen heavy profile covers every one of 238,226,172 instructions. Its
7,395 line evaluations contain 22,185 primitive calls. The existing wrapper
spends 4,259,520 instructions copying the accumulator prefix. One packet per
nonempty line bounds that work by 1,419,840 instructions, removing at least
2,839,680 **copy instructions** before compiler and loop effects. This is not
an instruction-total forecast or proving speedup. Reproduce the model without
running the guest:

```sh
python3 -m opstack.miller_packet_census --execution RETAINED_NATIVE_JSON --elf SELECTED_ELF --report model.json
```

The script pins ELF `72c23448…e930`, checks full PC coverage and cross-checks
service counts. Its PC authority is the selected ELF's wrapper at
`0x1ac344..0x1ac90c`, with ECALL at `0x1ac720`. The older 253M-instruction
Miller reports are not this baseline.

A synthetic two-line probe has five primitive calls, an intervening software
square, infinity/skip/all-skipped/empty paths, and an independently pinned
host result. Old per-group construction takes **20,039 instructions**; batching
**19,395**, with loads **3,361 → 3,097** and stores **6,646 → 6,356**. Both have
identical output, five calls and identical service RAM transition counts.
Unicorn and independent Python service arithmetic agree with the native
executor on output, exact instructions, endpoint, all registers and service
counts. These tiny figures are not extrapolated to block wall time.

Host debug and release each pass 17 tests. The packet test checks all prepared
Miller lines with 16 groups and five masks, including bit 15, infinity, all
skipped and empty inputs. It compares **each full packet**, rather than only
the final result. The diagnostic oracle mode cannot be accepted as OP output;
legacy V3 rejects the service tag.

Build the diagnostic using the lean crate's existing RV64 target, toolchain
`nightly-2026-08-08`, frontier profile, lower-atomic pass, build-std core/alloc
and feature `pairing-packet-probe`. It expects input `PKT1`. The oracle call is
`opstack.oracle.execute(config, native_steps, output_kind="pairing-packet-probe")`.
The normal candidate uses the same selected production features plus explicit
`pairing-packet-batching`; always regenerate ABI symbols from the resulting ELF.
Frozen configs, ELF images, control source and reports are retained in the
artifact directory recorded in the receipt. The control source wraps the
original `miller_line` implementation around the same synthetic group list.

The remaining larger frontier is whole-Miller lowering: this change keeps all
22,185 crossings and all provider arithmetic. Global self counts for Fp6 mul,
Fp12 square and Fp2 add are useful priorities, but not caller-exclusive Miller
counts; adding them as a claimed whole-Miller saving would overstate evidence.
