import subprocess,sys
opt=sys.argv[1] if len(sys.argv)>1 else 'ReleaseSafe'
base='.'
cmd=['zig','test','-O'+opt,'--test-filter','V3','--cache-dir','.zig-cache/products/riscv_cpu']
mods=[('root','src/integrations/riscv_cpu/rv64_truth_gkr_test_root.zig',['stwo_core','stwo_backend_contracts','stwo_prover_api','stwo_prover_engine','stwo_proof_wire','stwo_cpu_backend','stwo_riscv_frontend','interop_postcard','stwo_riscv_cpu_integration']),('stwo_core','src/core/mod.zig',[]),('stwo_backend_contracts','src/backend/mod.zig',['stwo_core']),('stwo_prover_api','src/prover_api/mod.zig',['stwo_core']),('stwo_prover_engine','src/prover/mod.zig',['stwo_core','stwo_backend_contracts','stwo_prover_api']),('stwo_proof_wire','src/interop/proof_wire/mod.zig',['stwo_core']),('stwo_cpu_backend','src/backends/cpu_scalar/mod.zig',['stwo_core','stwo_backend_contracts','stwo_prover_api','stwo_prover_engine']),('stwo_riscv_frontend','src/frontends/riscv/mod.zig',['stwo_core','stwo_backend_contracts','stwo_prover_api','stwo_prover_engine','interop_postcard']),('interop_postcard','src/interop/postcard.zig',['stwo_core','stwo_proof_wire']),('stwo_riscv_cpu_integration','src/integrations/riscv_cpu/mod.zig',['stwo_core','stwo_prover_api','stwo_prover_engine','stwo_cpu_backend','stwo_riscv_frontend','interop_postcard'])]
for name,path,deps in mods:
 cmd+=['-O'+opt]
 for d in deps:cmd+=['--dep',d]
 cmd+=['-M'+name+'='+path]
sys.exit(subprocess.call(cmd))
