from pathlib import Path
import subprocess,sys
repo=Path.cwd(); source=repo/'.git/local-ethereum/prepared-leaf-metal-source-v7/source'
checks=[(['python3',str(source/'scripts/zig_protocol_test.py'),'src/frontends/riscv/ethereum_leaf_context_v1_test_root.zig','--test-filter','Ethereum leaf context log18 admission remains explicit','-OReleaseSafe','-fstrip'],Path('/tmp/ethereum-keccak-context-log18-v3-frozen.log')),
(['python3','/tmp/build_prepared_metal_frozen_v7.py'],Path('/tmp/ethereum-prepared-metal-keccak-v7-build.log')),
(['python3','/tmp/build_ethereum_keccak_verifier_v6.py'],Path('/tmp/ethereum-keccak-verifier-v6-build.log')),
(['python3','/tmp/run_ethereum_real_metal_leaf11_log18_v2.py'],Path('/tmp/ethereum-real-metal-leaf11-log18-v2.log')),
(['python3','/tmp/verify_ethereum_real_metal_leaf11_log18_v2.py'],Path('/tmp/ethereum-real-metal-leaf11-log18-fresh-v2.log')),
(['python3','/tmp/prepare_ethereum_metal_campaign_log18_v3.py'],Path('/tmp/ethereum-metal-campaign-log18-prepare-v3.log'))]
for command,log in checks:
 print('Starting serialized stage:',str(log),flush=True)
 with log.open('xb') as output:result=subprocess.run(command,stdout=output,stderr=subprocess.STDOUT,cwd=repo)
 print('Stage terminal:',str(log),result.returncode,flush=True)
 if result.returncode:sys.exit(result.returncode)
print('Real leaf11 fresh acceptance and campaign migration preparation passed; inspect new launch pins before launch.',flush=True)
