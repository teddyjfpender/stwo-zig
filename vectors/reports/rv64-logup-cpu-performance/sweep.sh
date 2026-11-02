#!/bin/zsh
# usage: sweep.sh BIN OUT.jsonl < configs   (one config per line)
BIN=$1; OUT=$2
while read -r line; do
  [[ -z "$line" || "$line" == \#* ]] && continue
  load=$(sysctl -n vm.loadavg | awk '{print $2}')
  res=$($BIN ${=line} 2>&1)
  echo "{\"load1\":$load,\"cfg\":\"$line\",\"r\":$res}" >> $OUT
  echo "$line -> $res" | cut -c1-260
done
