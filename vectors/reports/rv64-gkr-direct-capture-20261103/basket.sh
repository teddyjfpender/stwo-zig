#!/bin/bash
# P4: old (main) vs new binary capture on each basket block. Prefix 1 on both; full capture (new) for blocks <= ~70M steps.
cd ~/Coding/ge-cache/directgkr/basket
OLD=~/Coding/ge-cache/fullblock/bin/bin/rv64-word16-ethereum-gkr
NEW=~/Coding/ge-cache/directgkr/bin5/bin/rv64-word16-ethereum-gkr
for n in 24626900 24628590 24628595 24628607 24628608 24628611 24647140 24697070 24697073 25229951 25229955 25229957 26235156 26235159 26235168; do
  ~/Coding/ge-ops/bin/memguard run --gb 8 --label directgkr-p4old-$n -- $OLD capture request-$n.json - 1 res-basket.json > old-$n.json 2> old-$n.err; echo "$n old_prefix1 rc=$? $(tail -c 120 old-$n.err | tr '\n' ' ')" >> summary.txt
  ~/Coding/ge-ops/bin/memguard run --gb 8 --label directgkr-p4new-$n -- $NEW capture request-$n.json - 1 res-basket.json > new1-$n.json 2> new1-$n.err; echo "$n new_prefix1 rc=$? $(tail -c 120 new1-$n.err | tr '\n' ' ')" >> summary.txt
done
for n in 26235156 24628607 24647140 25229957 24628608 24626900 24697070 24697073; do
  ~/Coding/ge-ops/bin/memguard run --gb 16 --label directgkr-p4full-$n -- /usr/bin/time -l $NEW capture request-$n.json - 0 res-basket.json > full-$n.json 2> full-$n.err; echo "$n new_full rc=$? $(grep 'maximum resident' full-$n.err)" >> summary.txt
done
echo DONE >> summary.txt
