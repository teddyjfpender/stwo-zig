# Alternating prefix-bank workspace

Progressive mixed-height Merkle leaves need two banks of unfinalized Blake
states. Each nonfinal distinct height writes the next bank while consuming the
previous one. Both banks previously reserved the largest nonfinal height.
`PrefixBanks` now records the maximum height actually assigned to each bank.
Equal-height column slabs do not advance the bank. The final height writes
hashes rather than a prefix state and needs no new bank.

For the largest observed recursive geometry, the nonfinal lifted heights are
9,15,17,19,21,22,24. The old scratch is 48*2^24 M31 words; the new scratch is
24*(2^24+2^22) words. This removes 301,989,888 words, or 1.125 GiB. This is an
exact allocation-size calculation, not a measured proving speedup.

Native rolling PCS uses this same planner for maximum workspace admission and
individual tree views. Trace commitment shrinks its caller-owned tail only
when the loaded runtime exports `stwo_rv64_trace_prefix_workspace_words`.
Older images retain the old allocation size; they must never silently fall
back to an untracked allocation because a new caller supplied a smaller tail.
Old callers can use the new runtime with their larger admitted tails.

Host tests cover all 65,536 subsets of sixteen heights, duplicate heights,
bank non-aliasing, maximum written rows, invalid input and the largest observed
geometry. Run with:

```
c++ -std=c++17 -Wall -Wextra -Werror src/backends/cuda/native/rv64/prefix_banks_test.cpp -o /tmp/prefix-banks-test
/tmp/prefix-banks-test
```

All three production semantic checks pass. Independent source review passes.
Tiny GPU cold/warm roots match CPU controls on both old and new runtimes,
and separate CPU receivers accept them. Largest-geometry allocation and full
basket qualification remain open; no complete-block speedup is claimed. No AIR, hash
protocol, transcript, field, security profile or proof encoding changes.
