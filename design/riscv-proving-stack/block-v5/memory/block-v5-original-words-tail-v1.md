# Original BLAKE3 input-frame tail sharing

This additive source batch preserves the original `Frame.words` byte encoding
and uses the existing compression Builder, G/XOR equations, byte router,
private-word bounds and public boundary AIR. It introduces no replacement hash
or original transcript change. Source qualification and proof execution are
separate: this candidate has not been compiled or run by its author.

An original word frame contains the27-byte protocol prefix, words-domain byte,
32-byte incoming channel digest, eight-byte little-endian word count, and exact
little-endian input words. Its68-byte header leaves956 input bytes in chunk0.
The next chunk starts at word239 byte0. The incoming channel digest differs by
execution/window, so a common sequential prefix compression context cannot be
reused. The BLAKE3 tree tail can be shared: every chunk at absolute index>=1 has
the same bytes, length, counter and flags for the independently expected input.

`blake3_words_tail_v1.Geometry` derives the exact inner-to-outer right siblings
of chunk0. These disjoint subtrees cover `[1,total_chunks)`, including an
unbalanced final sibling. `blake3_hash_plan.buildSubtreeAt` calls the original
Builder with those absolute indices and never enables ROOT. The additive
`buildPrefixFold` calls that same Builder for original chunk0, then unframed
parent compression with counter0, length64, PARENT, and ROOT only on the final
output. The old full-hash build path is unchanged. Single-chunk frames have no
tail and use original CHUNK_START/CHUNK_END/ROOT flags directly.

The isolated expected-input statement is **B5TI/v1**, whose root is exactly
`Frame.words(DOMAIN_STATE,input).hash()`. DOMAIN_STATE is the BLAKE3 digest of
`stwo-zig/block-v5/original-words-tail-input/v1` followed by a zero byte. This
provides separate input-commitment domain identity while retaining the same
68-byte original frame header and956-byte split. The root/length must come
from independently expected whole-job input. B5WM/v1's different input-root
recipe is incompatible and remains rejected for this route; metadata equality
cannot bridge these hashes.

`air/blake3_words_tail_witness_v1` emits the actual shared tail, input-root fold
and at most four original window folds. The same ranged private input-word
supplies feed every selected first chunk and every tail chunk. Tail CV public
constant sinks are removed: genuine hash output supplies feed byte routes into
all folds, with independently reconstructed multiplicities. The expected root
and original frame digest claims remain actual hash output sinks. Thus changing
input bytes, tail CVs, counters, flags, root claims or routed first-chunk bytes
cannot close the original recursion-wire tuple ledger while preserving the
independent preprocessing and public statements. Original incoming digest
bytes consume explicitly supplied original transcript endpoints; these
producers are mandatory, with exact returned use counts. A stand-alone graph
with those producers missing is open and cannot be accepted.

Trusted preprocessing independently regenerates the entire length/counter/
flag/wire schedule without evaluating compression or admitting a witness CV.
All graph and row allocations use the caller allocator; an explicit shared
budget lease survives the original budget-owner release and is dropped only
after owned rows are destroyed. Input/row limits and a four-window bound are
checked before allocation. These limits cover tracked allocations, not RSS.

Scalar fixtures compare against original `Frame.write`/`Frame.hash` and the
independent standard BLAKE3 implementation around word239/240 and total
chunk counts3,5,6,7,9 with partial final chunks. Generic Builder fixtures also
cover exact1024-byte single-chunk input, also reached by an original239-word
frame because68+4*239=1024. AIR fixtures cover direct equations,
exact tuple closure, absent original producers, state/message/claim mutations,
trusted geometry/multiplicity mutations, allocation failures and budget-owner
release. Body retention compiles actual additive Builder and witness functions;
it invokes no proof or device operation.

The current graph evaluates the tail once for its<=4 original frames and one
expected-input root. **Once-per-job reuse across multiple lower roots remains
open**: it requires a distinct proved tail public carrier exposing the exact
frontier CVs and first956 input bytes, an independently trusted key/public
schedule, genuine fresh/nested tail receivers and source byte supplies, and
selection of a new bounded public-root grammar. Carrying host CVs or a SHA
manifest is not that proof. Canonical B5WM activation, whole-job source
authority and complete global closure remain fail-closed until those actual
carrier and parent integration paths exist and are qualified.
