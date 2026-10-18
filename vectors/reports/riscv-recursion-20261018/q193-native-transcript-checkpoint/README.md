# q193 native/recursive transcript checkpoint

This is a **partial G-1/G-10 diagnostic**, not a qualified recursive proof.
At source revision `2757ed209`, the one-segment CPU setup generated a genuine
193-query native proof, destroyed the producer object, freshly decoded and
verified the proof, and prepared its recursive leaf. With
`STWO_RISCV_TRANSCRIPT_EQUIVALENCE=1`, the runner also compared the native
producer recording, fresh native verifier recording, and scheduled recursive
execution frame by frame. The comparisons and key setup returned exit 0.
No outer recursive proof was produced (`outer_proofs_created = 0`).

The retained input is `setup-manifest.json` plus its referenced
`child-0-expected.json`. `workload.json` and `tree-inputs.json` are the
upstream workload-export inputs. `run.log` is the exact command output and
`setup-result.json` contains the regenerated key and root pins. The large
generated key is reproducible and is not retained here.

Build and reproduce from the repository root with Zig 0.15.2:

```sh
zig build --build-file src/integrations/riscv_cpu/build.zig build-recursive-segment-v2-leaf-key-setup -Doptimize=ReleaseSafe -j2
STWO_RISCV_TRANSCRIPT_EQUIVALENCE=1 src/integrations/riscv_cpu/zig-out/bin/recursive-segment-v2-leaf-key-setup \
  vectors/reports/riscv-recursion-20261018/q193-native-transcript-checkpoint/setup-manifest.json \
  0ae6f1dd9821c32fe03c618c98c2abc9d24e9672b9c99f05ccaa86195d046dcf \
  /tmp/stwo-riscv-q193-transcript-new-output
```

The output directory must not already exist. The source revision and receipt
hashes for this run are:

| Artifact | SHA-256 |
| --- | --- |
| setup manifest | `0ae6f1dd9821c32fe03c618c98c2abc9d24e9672b9c99f05ccaa86195d046dcf` |
| expected child statement | `207c2bed378d85943bc3dd603ea84d9f035a93752634169140b20650030d2f46` |
| workload | `943d4802740889cabd3303d738a311a0ceff8801b4274a3cdc337b8dc3e9ebb7` |
| tree inputs | `8a8831cf124441e70d335ef5c106c3b6c4194b3c79a0d71c09c98c4fa9a4218c` |
| setup runner binary | `7ae8a086203b19692979c17bcac9909fc40a3918302a37bbb8b7f469fbf4b900` |
| generated child key | `35895d338572b3a4cc65ad93d3b2399986a28f46fce82525550b14dbd6162467` |
| setup result | `055f069a97da28a1a6fa77770d785c9cc3f6f738d5fe72f05c67c139e45c6243` |
| run log | `f94e609ea666b68a4f1c8465bb6fbbcaef31cfdfd69c48d94d77130e1c663160` |

The regenerated circuit identity is
`cdfe5d5cbf894eb54feb6f23544203dfd0bbc4e175a3301b567130fac93df90b`.
The outer Tree0 root is
`[540507341, 336814487, 815191153, 1222285710, 149956622, 1799311222, 511653249, 1024947236]`.
The native Tree0 root is
`[315791497, 1980036363, 1464907209, 1808642640, 591208445, 378136440, 1115843655, 681638299]`.

G-1 still requires its named test and every admitted profile. G-10 still
requires every leaf and parent in the complete 1/2/4/8 tree. G-8's hostile
proof control and proof-free parent-key Tree0 regeneration are also open.
